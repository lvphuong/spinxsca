import type { z } from 'zod';
import { repairJson } from '../llm/json-repair';
import { stripReasoning } from '../llm/openai-compatible';
import {
  addUsage,
  type ContentBlock,
  type Effort,
  type LlmProvider,
  type Message,
  type Usage,
  ZERO_USAGE,
} from '../llm/types';
import { estimateRequestTokens } from './compaction';
import { clampMaxTokens, contextBudgetFor } from './context-budget';
import { formatIssues, toolSpec } from './tools';
import type { AgentRunResult, AgentStep } from './types';

export interface StructuredOptions<O> {
  provider: LlmProvider;
  role: string;
  system: string;
  prompt: string;
  schema: z.ZodType<O>;
  /** Host-side checks beyond the schema; problems are sent back for another attempt. */
  validate?: (output: O) => Promise<string[]> | string[];
  /** Attempts including repairs (default 3). */
  maxAttempts?: number;
  maxOutputTokens?: number;
  effort?: Effort;
  signal?: AbortSignal;
  scanId?: string;
  costOf?: (usage: Usage, model: string) => number | undefined;
  maxCostUsd?: number;
}

/**
 * Single-shot structured extraction for models that cannot call tools (tool mode `none`, ADR-054):
 * the whole reply must be one JSON document matching the schema. Malformed JSON is repaired when
 * possible, schema and host-validation problems go back to the model with the full document asked
 * again, and the result has the shape of an agent run so records and ledgers need no special case.
 */
export async function runStructured<O>(options: StructuredOptions<O>): Promise<AgentRunResult<O>> {
  const spec = toolSpec('result', 'result', options.schema);
  const instruction = [
    options.prompt,
    '',
    'Reply with ONLY one JSON document (a single ```json fenced block, nothing before or after) that matches this schema:',
    '```json',
    JSON.stringify(spec.inputSchema),
    '```',
  ].join('\n');
  const messages: Message[] = [{ role: 'user', content: [{ type: 'text', text: instruction }] }];
  const steps: AgentStep[] = [];
  const models = new Set<string>();
  let usage: Usage = ZERO_USAGE;
  let cost: number | undefined;
  const budget = contextBudgetFor(options.provider.capabilities(), {
    maxOutputTokens: options.maxOutputTokens ?? 16_000,
  });
  const attempts = options.maxAttempts ?? 3;
  const finish = (status: AgentRunResult<O>['status'], extra: Partial<AgentRunResult<O>> = {}): AgentRunResult<O> => ({
    status,
    steps,
    usage,
    ...(cost !== undefined ? { costUsd: cost } : {}),
    models: [...models],
    ...extra,
  });
  for (let attempt = 0; attempt < attempts; attempt++) {
    if (options.signal?.aborted) return finish('CANCELLED');
    if (options.maxCostUsd !== undefined && cost !== undefined && cost > options.maxCostUsd)
      return finish('BUDGET_EXHAUSTED', { error: `cost budget of $${options.maxCostUsd} exhausted` });
    const estimated = estimateRequestTokens(options.system, [], messages);
    let result: Awaited<ReturnType<LlmProvider['complete']>>;
    try {
      result = await options.provider.complete(
        {
          system: options.system,
          messages,
          tools: [],
          maxTokens: clampMaxTokens(budget, estimated),
          responseSchema: spec.inputSchema,
          ...(options.effort ? { effort: options.effort } : {}),
          metadata: { role: options.role, ...(options.scanId ? { scanId: options.scanId } : {}) },
        },
        { ...(options.signal ? { signal: options.signal } : {}) },
      );
    } catch (err) {
      if (options.signal?.aborted) return finish('CANCELLED');
      return finish('FAILED', { error: err instanceof Error ? err.message : String(err) });
    }
    usage = addUsage(usage, result.usage);
    models.add(result.model);
    const stepCost = options.costOf?.(result.usage, result.model);
    if (stepCost !== undefined) cost = (cost ?? 0) + stepCost;
    steps.push({
      index: steps.length,
      stopReason: result.stopReason,
      model: result.model,
      usage: result.usage,
      toolCalls: [],
      fallbacks: result.fallbacks,
      contextTokens: estimated,
    });
    if (result.stopReason === 'refusal')
      return finish('REFUSED', { ...(result.refusal ? { refusal: result.refusal } : {}) });
    const text = stripReasoning(result.content.flatMap((b) => (b.type === 'text' ? [b.text] : [])).join('\n'));
    messages.push({ role: 'assistant', content: [{ type: 'text', text: text || '(empty)' }] });
    const repaired = repairJson(text);
    let problems: string[];
    if (!repaired) problems = ['the reply was not a JSON document'];
    else {
      const parsed = options.schema.safeParse(repaired.value);
      if (!parsed.success) problems = [formatIssues(parsed.error)];
      else {
        problems = options.validate ? await options.validate(parsed.data) : [];
        if (problems.length === 0) return finish('COMPLETED', { output: parsed.data });
      }
    }
    const fix: ContentBlock[] = [
      {
        type: 'text',
        text: `Problems with your reply:\n${problems.map((p) => `- ${p}`).join('\n')}\n\nReply again with the complete, corrected JSON document (one fenced json block, nothing else).`,
      },
    ];
    messages.push({ role: 'user', content: fix });
  }
  return finish('FAILED', { error: `no valid structured reply after ${attempts} attempts` });
}
