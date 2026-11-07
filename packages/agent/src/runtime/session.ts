import type { AgentStepRecord } from '@spinxsca/schemas';
import {
  addUsage,
  type ContentBlock,
  type Effort,
  type LlmProvider,
  type Message,
  RetryableTurnError,
  type StopReason,
  type Usage,
  ZERO_USAGE,
} from '../llm/types';
import { type CompactionOptions, compactionFor, compactOutbound } from './compaction';
import { clampMaxTokens, contextBudgetFor } from './context-budget';
import { PlainToolExecutor, type ToolExecutor, type ToolOutcome, type ToolUse } from './executor';
import { createReadResultTool, MemoryResultStore, READ_RESULT_TOOL, type ResultStore } from './result-store';
import { type AgentTool, formatIssues, type SubmitTool, toolSpec } from './tools';
import { MemorySessionStore, messagesFrom, type SessionStore } from './transcript';
import { type AgentBudget, type AgentRunResult, type AgentStatus, type AgentStep, DEFAULT_BUDGET } from './types';

export interface SessionOptions<O> {
  /** Stable id of the run; checkpoints are keyed by it, so the same id resumes the run. */
  runId: string;
  caseId?: string;
  role: string;
  provider: LlmProvider;
  system: string;
  prompt: string;
  /** Tools offered to the model (specs); execution goes through `executor`. */
  tools: readonly AgentTool[];
  submit: SubmitTool<O>;
  executor?: ToolExecutor;
  store?: SessionStore;
  budget?: Partial<AgentBudget>;
  effort?: Effort;
  signal?: AbortSignal;
  scanId?: string;
  onStep?: (step: AgentStep) => void;
  maxCostUsd?: number;
  costOf?: (usage: Usage, model: string) => number | undefined;
  /** Called after every model response (ledger charging). */
  onUsage?: (usage: Usage, model: string, costUsd: number | undefined) => Promise<void> | void;
  /** Checked before every model call; a returned reason ends the run as BUDGET_EXHAUSTED. */
  budgetGuard?: () => Promise<string | undefined> | string | undefined;
  /** Wall-clock deadline (epoch ms). */
  deadline?: number;
  compaction?: CompactionOptions;
  /** Store for tool results beyond the inline budget (ADR-056); session memory when absent. */
  resultStore?: ResultStore;
  /** Model-written compaction summary (ADR-056); deterministic summary when absent or failing. */
  summarizer?: CompactionOptions['summarize'];
  now?: () => Date;
}

export type SessionStatus = AgentStatus | 'SUSPENDED';

export interface SessionResult<O> extends Omit<AgentRunResult<O>, 'status'> {
  status: SessionStatus;
  /** Set when the run waits for a human decision. */
  suspendedOn?: { reason: string; approvalIds: string[] };
  /** True when the run continued from earlier checkpoints. */
  resumed: boolean;
}

const MAX_NUDGES = 2;
const MAX_TURN_RETRIES = 2;
const MAX_CONTEXT_COLLAPSES = 2;
const MAX_PARSE_REPAIRS = 2;
const MAX_LENGTH_RECOVERIES = 2;

/**
 * Durable, governed tool-use session (ADR-042). Same contract as the minimal loop (append-only
 * history, one user message with all tool results of a turn, schema-validated deliverable, hard
 * budgets) plus checkpoints after every turn, resumption from the last checkpoint, suspension while
 * a human decides, outbound compaction and an injectable executor (the policy engine for cases).
 */
export async function runAgentSession<O>(options: SessionOptions<O>): Promise<SessionResult<O>> {
  const budget = { ...DEFAULT_BUDGET, ...options.budget };
  // The provider's window sizes compaction and max_tokens (ADR-053); compaction is always on.
  const ctxBudget = contextBudgetFor(options.provider.capabilities(), budget);
  let compaction: CompactionOptions = {
    ...(options.compaction ?? compactionFor(ctxBudget)),
    ...(options.summarizer ? { summarize: options.summarizer } : {}),
  };
  let compactions = 0;
  let collapses = 0;
  let parseRepairs = 0;
  let lengthRecoveries = 0;
  const store = options.store ?? new MemorySessionStore();
  // Large tool results leave the window (ADR-056): the default executor stores them and offers read_result.
  const results = options.resultStore ?? new MemoryResultStore();
  const tools: readonly AgentTool[] =
    options.executor || options.tools.some((t) => t.name === READ_RESULT_TOOL)
      ? options.tools
      : [...options.tools, createReadResultTool(results, ctxBudget.inlineResultChars)];
  const executor =
    options.executor ?? new PlainToolExecutor(tools, { inlineChars: ctxBudget.inlineResultChars, store: results });
  const now = options.now ?? (() => new Date());
  const toolNames = new Set(tools.map((t) => t.name));
  if (toolNames.has(options.submit.name))
    throw new Error(`tool name ${options.submit.name} is reserved for submission`);
  const specs = [
    ...tools.map((t) => toolSpec(t.name, t.description, t.input)),
    // The deliverable is a large nested object: buffered input lets the server repair malformed JSON
    // into a value the schema check can reject with feedback, instead of a turn that fails on retry.
    { ...toolSpec(options.submit.name, options.submit.description, options.submit.output), eagerInput: false },
  ];

  // Restore checkpoints.
  const saved = (await store.load(options.runId)).sort((a, b) => a.index - b.index);
  const resumed = saved.length > 0;
  const messages: Message[] = messagesFrom(saved);
  const steps: AgentStep[] = [];
  const models = new Set<string>();
  let usage: Usage = ZERO_USAGE;
  let toolCalls = 0;
  let nudges = 0;
  let cost: number | undefined;
  for (const s of saved) {
    if (s.kind === 'turn') {
      steps.push({
        index: steps.length,
        stopReason: s.stopReason ?? 'other',
        model: s.model ?? 'unknown',
        usage: s.usage ?? ZERO_USAGE,
        toolCalls: [],
        fallbacks: [],
      });
      if (s.usage) usage = addUsage(usage, s.usage);
      if (s.model) {
        models.add(s.model);
        const c = s.usage ? options.costOf?.(s.usage, s.model) : undefined;
        if (c !== undefined) cost = (cost ?? 0) + c;
      }
    } else if (s.kind === 'results') {
      const last = steps.at(-1);
      for (const b of s.content as ContentBlock[]) {
        if (b.type !== 'tool_result') continue;
        toolCalls++;
        last?.toolCalls.push({ name: toolNameOf(saved, b.toolUseId), ok: !b.isError });
      }
    }
  }
  let nextIndex = saved.length ? (saved.at(-1) as AgentStepRecord).index + 1 : 0;
  const checkpoint = async (
    kind: AgentStepRecord['kind'],
    content: ContentBlock[],
    extra: Partial<AgentStepRecord> = {},
  ) => {
    await store.save({
      agentRunId: options.runId,
      caseId: options.caseId ?? '',
      index: nextIndex++,
      kind,
      content,
      at: now().toISOString(),
      ...extra,
    });
  };
  if (!resumed) {
    const first: ContentBlock[] = [{ type: 'text', text: options.prompt }];
    messages.push({ role: 'user', content: first });
    await checkpoint('prompt', first);
  }

  const finish = (status: SessionStatus, extra: Partial<SessionResult<O>> = {}): SessionResult<O> => ({
    status,
    steps,
    usage,
    ...(cost !== undefined ? { costUsd: cost } : {}),
    models: [...models],
    resumed,
    compactions,
    ...extra,
  });

  // A run that already submitted returns its deliverable: resuming never repeats a finished run.
  const accepted = acceptedSubmission(saved, options.submit);
  if (accepted) return finish('COMPLETED', { output: accepted.value });

  // A run checkpointed right after a model turn resumes by executing that turn's tool calls.
  let pending: { content: ContentBlock[]; stopReason: StopReason; step: AgentStep } | undefined;
  const lastSaved = saved.at(-1);
  if (lastSaved?.kind === 'turn') {
    pending = {
      content: lastSaved.content as ContentBlock[],
      stopReason: (lastSaved.stopReason as StopReason | undefined) ?? 'tool_use',
      step: steps.at(-1) as AgentStep,
    };
  }
  let retries = 0;

  while (true) {
    if (!pending) {
      if (options.signal?.aborted) return finish('CANCELLED');
      if (steps.length >= budget.maxSteps) return finish('BUDGET_EXHAUSTED');
      if (options.deadline !== undefined && Date.now() > options.deadline) {
        return finish('BUDGET_EXHAUSTED', { error: 'wall-clock budget exhausted' });
      }
      const guard = await options.budgetGuard?.();
      if (guard) return finish('BUDGET_EXHAUSTED', { error: guard });
      const view = await compactOutbound(messages, compaction, { system: options.system, tools: specs });
      if (view.summarized) compactions++;
      const outbound = view.messages;
      const estimatedInput = view.estimatedTokens;
      let result: Awaited<ReturnType<LlmProvider['complete']>>;
      try {
        result = await options.provider.complete(
          {
            system: options.system,
            messages: outbound,
            tools: specs,
            maxTokens: clampMaxTokens(ctxBudget, estimatedInput),
            toolChoice: nudges > 0 ? 'required' : 'auto',
            ...(options.effort ? { effort: options.effort } : {}),
            metadata: { role: options.role, ...(options.scanId ? { scanId: options.scanId } : {}) },
          },
          { ...(options.signal ? { signal: options.signal } : {}) },
        );
        retries = 0;
      } catch (err) {
        if (options.signal?.aborted) return finish('CANCELLED');
        if (err instanceof RetryableTurnError) {
          if (err.kind === 'context' && collapses++ < MAX_CONTEXT_COLLAPSES) {
            // The request did not fit: tighten the view until the reported gap (or half) is gone.
            const gap = err.detail?.actual && err.detail?.limit ? err.detail.actual - err.detail.limit : undefined;
            const target = gap ? estimatedInput - gap - ctxBudget.buffer : Math.floor(estimatedInput * 0.5);
            compaction = {
              ...compaction,
              thresholdTokens: Math.max(512, Math.min(compaction.thresholdTokens, target)),
              keepTurns: Math.max(1, compaction.keepTurns - 2),
              microcompact: { keepRecent: 2, tools: compaction.microcompact?.tools ?? new Set<string>() },
            };
            continue;
          }
          if (err.kind === 'parse' && err.rawText !== undefined && parseRepairs++ < MAX_PARSE_REPAIRS) {
            // Show the model its own unusable reply and ask for a corrected one instead of an identical retry.
            const bad: ContentBlock[] = [{ type: 'text', text: err.rawText.slice(0, 4_000) || '(empty reply)' }];
            messages.push({ role: 'assistant', content: bad });
            await checkpoint('turn', bad, { stopReason: 'other' });
            const fix: ContentBlock[] = [
              {
                type: 'text',
                text: `Your previous reply could not be used: ${err.message}. Reply again and call exactly one tool with valid JSON arguments.`,
              },
            ];
            messages.push({ role: 'user', content: fix });
            await checkpoint('results', fix);
            continue;
          }
          if (err.kind === 'transient' && retries++ < MAX_TURN_RETRIES) continue;
        }
        return finish('FAILED', { error: err instanceof Error ? err.message : String(err) });
      }
      usage = addUsage(usage, result.usage);
      models.add(result.model);
      const stepCost = options.costOf?.(result.usage, result.model);
      if (stepCost !== undefined) cost = (cost ?? 0) + stepCost;
      await options.onUsage?.(result.usage, result.model, stepCost);
      const step: AgentStep = {
        index: steps.length,
        stopReason: result.stopReason,
        model: result.model,
        usage: result.usage,
        toolCalls: [],
        fallbacks: result.fallbacks,
        contextTokens: estimatedInput,
      };
      steps.push(step);
      if (result.stopReason === 'refusal') {
        options.onStep?.(step);
        return finish('REFUSED', { ...(result.refusal ? { refusal: result.refusal } : {}) });
      }
      messages.push({ role: 'assistant', content: result.content });
      await checkpoint('turn', result.content, {
        model: result.model,
        stopReason: result.stopReason,
        usage: result.usage,
      });
      pending = { content: result.content, stopReason: result.stopReason, step };
    }

    const { content, stopReason, step } = pending;
    pending = undefined;
    const toolUses = content.filter((b): b is ToolUse => b.type === 'tool_use');

    if (stopReason === 'max_tokens' && toolUses.length > 0) {
      options.onStep?.(step);
      return finish('FAILED', { error: 'tool input truncated at max_tokens; raise maxOutputTokens' });
    }
    if (toolUses.length === 0) {
      options.onStep?.(step);
      if (stopReason === 'pause_turn') continue;
      if (stopReason === 'max_tokens' && lengthRecoveries++ < MAX_LENGTH_RECOVERIES) {
        // The answer was cut, not refused: ask the model to continue in smaller pieces (no nudge spent).
        const resume: ContentBlock[] = [
          {
            type: 'text',
            text: 'Output token limit hit. Resume directly without a recap; break the remaining work into smaller tool calls and call the tool when ready.',
          },
        ];
        messages.push({ role: 'user', content: resume });
        await checkpoint('results', resume);
        continue;
      }
      if (nudges++ >= MAX_NUDGES) return finish('FAILED', { error: 'model ended without calling the submit tool' });
      const nudge: ContentBlock[] = [
        { type: 'text', text: `Finish by calling the \`${options.submit.name}\` tool with your result.` },
      ];
      messages.push({ role: 'user', content: nudge });
      await checkpoint('results', nudge);
      continue;
    }

    const results: ContentBlock[] = [];
    let submitted: { value: O } | undefined;
    const suspended: string[] = [];
    let suspendReason: string | undefined;
    let stop: string | undefined;
    for (const call of toolUses) {
      const reply = (text: string, isError = false): void => {
        results.push({ type: 'tool_result', toolUseId: call.id, content: text, ...(isError ? { isError: true } : {}) });
        step.toolCalls.push({ name: call.name, ok: !isError });
      };
      if (stop) {
        reply('Not executed: the run was stopped.', true);
        continue;
      }
      if (options.signal?.aborted) {
        reply('Cancelled before execution.', true);
        continue;
      }
      toolCalls++;
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
      let outcome: ToolOutcome;
      try {
        outcome = await executor.execute(call, { ...(options.signal ? { signal: options.signal } : {}) });
      } catch (err) {
        outcome = {
          kind: 'result',
          content: `Tool ${call.name} failed: ${err instanceof Error ? err.message : String(err)}`,
          isError: true,
        };
      }
      if (outcome.kind === 'suspend') {
        toolCalls--;
        suspendReason = outcome.reason;
        if (outcome.approvalId) suspended.push(outcome.approvalId);
        continue;
      }
      if (outcome.kind === 'stop') {
        reply(outcome.content, true);
        stop = outcome.reason;
        continue;
      }
      reply(outcome.content, outcome.isError ?? false);
      const last = step.toolCalls.at(-1);
      if (last) {
        if (outcome.decision) Object.assign(last, { decision: outcome.decision });
        if (outcome.argsDigest) Object.assign(last, { argsDigest: outcome.argsDigest });
        if (outcome.outputDigest) Object.assign(last, { outputDigest: outcome.outputDigest });
        Object.assign(last, { id: call.id });
      }
    }

    if (suspendReason !== undefined && !stop) {
      // Results are not checkpointed: on resume the turn is replayed; finished calls come back from
      // the executor's durable record, the parked one runs once a human has decided.
      options.onStep?.(step);
      return finish('SUSPENDED', { suspendedOn: { reason: suspendReason, approvalIds: suspended } });
    }
    messages.push({ role: 'user', content: results });
    await checkpoint('results', results);
    options.onStep?.(step);
    if (options.signal?.aborted) return finish('CANCELLED');
    if (stop) return finish('FAILED', { error: stop });
    if (submitted) return finish('COMPLETED', { output: submitted.value });
    if (usage.inputTokens + usage.outputTokens > budget.maxTotalTokens) {
      return finish('BUDGET_EXHAUSTED', { error: 'token budget exhausted' });
    }
    if (options.maxCostUsd !== undefined && cost !== undefined && cost > options.maxCostUsd) {
      return finish('BUDGET_EXHAUSTED', { error: `cost budget of $${options.maxCostUsd} exhausted` });
    }
  }
}

function acceptedSubmission<O>(steps: readonly AgentStepRecord[], submit: SubmitTool<O>): { value: O } | undefined {
  for (const s of [...steps].reverse()) {
    if (s.kind !== 'results') continue;
    for (const b of s.content as ContentBlock[]) {
      if (b.type !== 'tool_result' || b.isError || b.content !== 'Submission accepted.') continue;
      for (const t of steps) {
        if (t.kind !== 'turn') continue;
        for (const u of t.content as ContentBlock[]) {
          if (u.type === 'tool_use' && u.id === b.toolUseId && u.name === submit.name) {
            const parsed = submit.output.safeParse(u.input);
            if (parsed.success) return { value: parsed.data };
          }
        }
      }
    }
    return undefined;
  }
  return undefined;
}

function toolNameOf(steps: readonly AgentStepRecord[], toolUseId: string): string {
  for (const s of steps) {
    if (s.kind !== 'turn') continue;
    for (const b of s.content as ContentBlock[]) if (b.type === 'tool_use' && b.id === toolUseId) return b.name;
  }
  return 'unknown';
}
