import {
  addUsage,
  type ContentBlock,
  type Effort,
  type LlmProvider,
  type Message,
  RetryableTurnError,
  type Usage,
  ZERO_USAGE,
} from '../llm/types';
import { type AgentTool, formatIssues, type SubmitTool, toolSpec } from './tools';

export interface AgentBudget {
  maxSteps: number;
  maxToolCalls: number;
  /** Input + output tokens across all turns. */
  maxTotalTokens: number;
  /** Per-response output cap. */
  maxOutputTokens: number;
}

export const DEFAULT_BUDGET: AgentBudget = {
  maxSteps: 30,
  maxToolCalls: 60,
  maxTotalTokens: 400_000,
  maxOutputTokens: 32_000,
};

export interface AgentRunOptions<O> {
  role: string;
  provider: LlmProvider;
  system: string;
  prompt: string;
  tools: AgentTool<never>[] | AgentTool[];
  submit: SubmitTool<O>;
  budget?: Partial<AgentBudget>;
  effort?: Effort;
  signal?: AbortSignal;
  scanId?: string;
  onStep?: (step: AgentStep) => void;
  /** Stops the run once the accumulated cost exceeds this amount (needs `costOf`). */
  maxCostUsd?: number;
  costOf?: (usage: Usage, model: string) => number | undefined;
}

export interface AgentStep {
  index: number;
  stopReason: string;
  model: string;
  usage: Usage;
  toolCalls: Array<{ name: string; ok: boolean }>;
  fallbacks: Array<{ from: string; to: string }>;
}

export type AgentStatus = 'COMPLETED' | 'BUDGET_EXHAUSTED' | 'REFUSED' | 'FAILED' | 'CANCELLED';

export interface AgentRunResult<O> {
  status: AgentStatus;
  output?: O;
  steps: AgentStep[];
  usage: Usage;
  /** Priced cost of the run, when the models are in the price table. */
  costUsd?: number;
  /** Every model that produced output during the run (audit of fallbacks). */
  models: string[];
  error?: string;
  refusal?: { category?: string; explanation?: string };
}

const MAX_NUDGES = 2;
const MAX_TURN_RETRIES = 2;

/**
 * Minimal tool-use loop (docs/architecture/03 section 8): append-only history, all tool results of a
 * turn returned in one user message, schema-validated inputs, explicit stop-reason handling and hard
 * budgets. The run ends only when the submit tool receives a valid deliverable.
 */
export async function runAgent<O>(options: AgentRunOptions<O>): Promise<AgentRunResult<O>> {
  const budget = { ...DEFAULT_BUDGET, ...options.budget };
  const tools = new Map<string, AgentTool>((options.tools as AgentTool[]).map((t) => [t.name, t]));
  if (tools.has(options.submit.name)) throw new Error(`tool name ${options.submit.name} is reserved for submission`);
  const specs = [
    ...[...tools.values()].map((t) => toolSpec(t.name, t.description, t.input)),
    // The deliverable is a large nested object: buffered input lets the server repair malformed JSON
    // into a value the schema check can reject with feedback, instead of a turn that fails on retry.
    { ...toolSpec(options.submit.name, options.submit.description, options.submit.output), eagerInput: false },
  ];
  const messages: Message[] = [{ role: 'user', content: [{ type: 'text', text: options.prompt }] }];
  const steps: AgentStep[] = [];
  const models = new Set<string>();
  let usage: Usage = ZERO_USAGE;
  let toolCalls = 0;
  let nudges = 0;
  let retries = 0;
  let cost: number | undefined;

  const finish = (status: AgentStatus, extra: Partial<AgentRunResult<O>> = {}): AgentRunResult<O> => ({
    status,
    steps,
    usage,
    ...(cost !== undefined ? { costUsd: cost } : {}),
    models: [...models],
    ...extra,
  });

  for (let index = 0; index < budget.maxSteps; index++) {
    if (options.signal?.aborted) return finish('CANCELLED');
    let result: Awaited<ReturnType<LlmProvider['complete']>>;
    try {
      result = await options.provider.complete(
        {
          system: options.system,
          messages,
          tools: specs,
          maxTokens: budget.maxOutputTokens,
          ...(options.effort ? { effort: options.effort } : {}),
          metadata: { role: options.role, ...(options.scanId ? { scanId: options.scanId } : {}) },
        },
        { ...(options.signal ? { signal: options.signal } : {}) },
      );
      retries = 0;
    } catch (err) {
      if (options.signal?.aborted) return finish('CANCELLED');
      if (err instanceof RetryableTurnError && retries++ < MAX_TURN_RETRIES) {
        index--;
        continue;
      }
      return finish('FAILED', { error: err instanceof Error ? err.message : String(err) });
    }
    usage = addUsage(usage, result.usage);
    models.add(result.model);
    const stepCost = options.costOf?.(result.usage, result.model);
    if (stepCost !== undefined) cost = (cost ?? 0) + stepCost;
    const step: AgentStep = {
      index,
      stopReason: result.stopReason,
      model: result.model,
      usage: result.usage,
      toolCalls: [],
      fallbacks: result.fallbacks,
    };
    steps.push(step);

    if (result.stopReason === 'refusal') {
      options.onStep?.(step);
      return finish('REFUSED', { ...(result.refusal ? { refusal: result.refusal } : {}) });
    }
    messages.push({ role: 'assistant', content: result.content });
    const toolUses = result.content.filter(
      (b): b is Extract<ContentBlock, { type: 'tool_use' }> => b.type === 'tool_use',
    );

    if (result.stopReason === 'max_tokens' && toolUses.length > 0) {
      options.onStep?.(step);
      return finish('FAILED', { error: 'tool input truncated at max_tokens; raise maxOutputTokens' });
    }
    if (toolUses.length === 0) {
      options.onStep?.(step);
      if (result.stopReason === 'pause_turn') continue;
      if (nudges++ >= MAX_NUDGES) return finish('FAILED', { error: 'model ended without calling the submit tool' });
      messages.push({
        role: 'user',
        content: [{ type: 'text', text: `Finish by calling the \`${options.submit.name}\` tool with your result.` }],
      });
      continue;
    }

    const results: ContentBlock[] = [];
    let submitted: { value: O } | undefined;
    for (const call of toolUses) {
      toolCalls++;
      const reply = (content: string, isError = false): void => {
        results.push({ type: 'tool_result', toolUseId: call.id, content, ...(isError ? { isError: true } : {}) });
        step.toolCalls.push({ name: call.name, ok: !isError });
      };
      if (toolCalls > budget.maxToolCalls && call.name !== options.submit.name) {
        reply(
          `Tool budget exhausted. Call \`${options.submit.name}\` now with what you have, listing unfinished work as deferred.`,
          true,
        );
        continue;
      }
      if (call.name === options.submit.name) {
        const parsed = options.submit.output.safeParse(call.input);
        const problems = parsed.success && options.submit.validate ? await options.submit.validate(parsed.data) : [];
        if (parsed.success && problems.length > 0) {
          reply(
            `Submission rejected. Fix these problems and call ${options.submit.name} again:\n${problems.map((p) => `- ${p}`).join('\n')}`,
            true,
          );
        } else if (parsed.success) {
          submitted = { value: parsed.data };
          reply('Submission accepted.');
        } else {
          reply(
            `Submission rejected. Fix these fields and call ${options.submit.name} again:\n${formatIssues(parsed.error)}`,
            true,
          );
        }
        continue;
      }
      const tool = tools.get(call.name);
      if (!tool) {
        reply(`Unknown tool ${call.name}.`, true);
        continue;
      }
      const parsed = tool.input.safeParse(call.input);
      if (!parsed.success) {
        reply(`Invalid input for ${call.name}:\n${formatIssues(parsed.error)}`, true);
        continue;
      }
      try {
        reply(await tool.run(parsed.data, { ...(options.signal ? { signal: options.signal } : {}) }));
      } catch (err) {
        reply(`Tool ${call.name} failed: ${err instanceof Error ? err.message : String(err)}`, true);
      }
    }
    options.onStep?.(step);
    if (submitted) return finish('COMPLETED', { output: submitted.value });
    messages.push({ role: 'user', content: results });
    if (usage.inputTokens + usage.outputTokens > budget.maxTotalTokens)
      return finish('BUDGET_EXHAUSTED', { error: 'token budget exhausted' });
    if (options.maxCostUsd !== undefined && cost !== undefined && cost > options.maxCostUsd) {
      return finish('BUDGET_EXHAUSTED', { error: `cost budget of $${options.maxCostUsd} exhausted` });
    }
  }
  return finish('BUDGET_EXHAUSTED');
}
