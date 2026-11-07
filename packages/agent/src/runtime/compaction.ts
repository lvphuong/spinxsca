import type { ContentBlock, Message, ToolSpec } from '../llm/types';
import type { ContextBudget } from './context-budget';

export interface MicrocompactOptions {
  /** Most recent compactable tool results kept verbatim. */
  keepRecent: number;
  /** Tools whose old results can be cleared: the model can re-read them. */
  tools: ReadonlySet<string>;
}

export interface CompactionOptions {
  /** Compact the outbound view once the request is estimated above this many tokens. */
  thresholdTokens: number;
  /** Most recent assistant turns kept verbatim (with their tool results). */
  keepTurns: number;
  /** Optional model-written summary; the deterministic summary is used when absent or failing. */
  summarize?: (dropped: readonly Message[]) => Promise<string>;
  /** Clears old read-only tool results before summarising (ADR-056); off when absent. */
  microcompact?: MicrocompactOptions;
}

/** Legacy fixed options; sessions now derive theirs from the provider window (`compactionFor`). */
export const DEFAULT_COMPACTION: CompactionOptions = { thresholdTokens: 120_000, keepTurns: 6 };

/** Read-only tools whose results can be dropped from the view: the model re-reads if it needs them. */
export const COMPACTABLE_TOOLS: ReadonlySet<string> = new Set([
  'read_file',
  'search_code',
  'list_files',
  'read_result',
  'repo_map',
  'resource_matrix',
  'data_access_sites',
  'list_endpoints',
  'callers',
  'callees',
  'find_symbol',
  'shell_exec',
]);

/** Compaction sized for one context budget (ADR-053). */
export function compactionFor(budget: ContextBudget): CompactionOptions {
  return {
    thresholdTokens: budget.compactThreshold,
    keepTurns: budget.window >= 100_000 ? 6 : 3,
    microcompact: { keepRecent: 5, tools: COMPACTABLE_TOOLS },
  };
}

/** Rough token estimate (4 characters per token) of the transcript alone. */
export function estimateTokens(messages: readonly Message[]): number {
  let chars = 0;
  for (const m of messages) {
    for (const b of m.content) {
      if (b.type === 'text') chars += b.text.length;
      else if (b.type === 'tool_result') chars += b.content.length;
      else if (b.type === 'tool_use') chars += JSON.stringify(b.input).length + b.name.length;
      else chars += 200;
    }
  }
  return Math.ceil(chars / 4);
}

/** Estimate of a whole request: system prompt and tool schemas count too (several thousand tokens). */
export function estimateRequestTokens(
  system: string,
  tools: readonly ToolSpec[],
  messages: readonly Message[],
): number {
  const schema = tools.reduce(
    (n, t) => n + t.name.length + t.description.length + JSON.stringify(t.inputSchema).length,
    0,
  );
  return Math.ceil((system.length + schema) / 4) + estimateTokens(messages);
}

export interface CompactionRequest {
  system: string;
  tools: readonly ToolSpec[];
}

export interface CompactedView {
  messages: Message[];
  /** Old tool results were cleared. */
  microcompacted: boolean;
  /** The middle of the transcript was replaced by a summary. */
  summarized: boolean;
  /** Estimated tokens of the returned view including system and tools when given. */
  estimatedTokens: number;
}

/**
 * Outbound-only compaction (ADR-042): the durable transcript is never rewritten. Ladder (ADR-056):
 * from 60% of the threshold old read-only tool results are cleared; above the threshold the middle
 * is replaced by a summary and the last turns are kept intact, starting at an assistant turn so no
 * tool_result loses its tool_use.
 */
export async function compactOutbound(
  messages: readonly Message[],
  options: CompactionOptions,
  request?: CompactionRequest,
): Promise<CompactedView> {
  const estimate = (view: readonly Message[]) =>
    request ? estimateRequestTokens(request.system, request.tools, view) : estimateTokens(view);
  let view: Message[] = [...messages];
  let microcompacted = false;
  let size = estimate(view);
  if (options.microcompact && size > options.thresholdTokens * 0.6) {
    const cleared = microcompact(view, options.microcompact);
    if (cleared.changed) {
      view = cleared.messages;
      microcompacted = true;
      size = estimate(view);
    }
  }
  if (size <= options.thresholdTokens)
    return { messages: view, microcompacted, summarized: false, estimatedTokens: size };
  const assistantIdx = view.map((m, i) => (m.role === 'assistant' ? i : -1)).filter((i) => i > 0);
  if (assistantIdx.length <= options.keepTurns)
    return { messages: view, microcompacted, summarized: false, estimatedTokens: size };
  const cut = assistantIdx[assistantIdx.length - options.keepTurns] as number;
  const dropped = view.slice(1, cut);
  let summary: string;
  try {
    summary = options.summarize ? await options.summarize(dropped) : deterministicSummary(dropped);
  } catch {
    summary = deterministicSummary(dropped);
  }
  const prompt = view[0] as Message;
  const head: Message = {
    role: 'user',
    content: [
      ...prompt.content,
      {
        type: 'text',
        text: `<earlier_work_summary turns="${dropped.filter((m) => m.role === 'assistant').length}">\n${summary}\n</earlier_work_summary>\nContinue from where the summary ends.`,
      },
    ],
  };
  const out = [head, ...view.slice(cut)];
  return { messages: out, microcompacted, summarized: true, estimatedTokens: estimate(out) };
}

/** Same as `compactOutbound` returning only the messages (kept for callers and tests). */
export async function compactView(
  messages: readonly Message[],
  options: CompactionOptions,
  request?: CompactionRequest,
): Promise<Message[]> {
  return (await compactOutbound(messages, options, request)).messages;
}

/**
 * Replaces every compactable tool result except the `keepRecent` newest with a one-line stub that
 * still names the tool and its path, so the files-examined list survives and the model knows what
 * to re-read.
 */
export function microcompact(
  messages: readonly Message[],
  options: MicrocompactOptions,
): { messages: Message[]; changed: boolean } {
  const uses = new Map<string, { name: string; input: unknown }>();
  for (const m of messages) {
    if (m.role !== 'assistant') continue;
    for (const b of m.content) if (b.type === 'tool_use') uses.set(b.id, { name: b.name, input: b.input });
  }
  const compactable: string[] = [];
  for (const m of messages) {
    if (m.role !== 'user') continue;
    for (const b of m.content) {
      if (b.type !== 'tool_result') continue;
      const use = uses.get(b.toolUseId);
      if (use && options.tools.has(use.name) && !b.content.startsWith(CLEARED_PREFIX)) compactable.push(b.toolUseId);
    }
  }
  const clear = new Set(compactable.slice(0, Math.max(0, compactable.length - options.keepRecent)));
  if (clear.size === 0) return { messages: [...messages], changed: false };
  const out = messages.map((m) => {
    if (m.role !== 'user' || !m.content.some((b) => b.type === 'tool_result' && clear.has(b.toolUseId))) return m;
    return {
      ...m,
      content: m.content.map((b): ContentBlock => {
        if (b.type !== 'tool_result' || !clear.has(b.toolUseId)) return b;
        const use = uses.get(b.toolUseId);
        const path = (use?.input as { path?: unknown } | undefined)?.path;
        const target = typeof path === 'string' ? `(${path})` : '';
        return {
          ...b,
          content: `${CLEARED_PREFIX} ${use?.name ?? 'tool'}${target} cleared to save context; call it again if the content is needed]`,
        };
      }),
    };
  });
  return { messages: out, changed: true };
}

const CLEARED_PREFIX = '[earlier result of';

const SECTION_LIMIT = 1500;

/** Eight fixed sections built from the dropped turns without a model call. */
export function deterministicSummary(dropped: readonly Message[]): string {
  const calls: string[] = [];
  const errors: string[] = [];
  const files = new Set<string>();
  const notes: string[] = [];
  const results: string[] = [];
  for (const m of dropped) {
    for (const b of m.content as ContentBlock[]) {
      if (b.type === 'tool_use') {
        const input = JSON.stringify(b.input);
        calls.push(`${b.name}(${input.slice(0, 160)})`);
        const path = (b.input as { path?: unknown })?.path;
        if (typeof path === 'string') files.add(path);
      } else if (b.type === 'tool_result') {
        (b.isError ? errors : results).push(b.content.replace(/\s+/g, ' ').slice(0, 200));
      } else if (b.type === 'text' && m.role === 'assistant') {
        notes.push(b.text.replace(/\s+/g, ' ').slice(0, 300));
      }
    }
  }
  const section = (title: string, lines: string[]) =>
    `## ${title}\n${lines.length ? lines.join('\n').slice(0, SECTION_LIMIT) : '(none)'}`;
  return [
    section('1. Task', ['See the original request above; it is unchanged.']),
    section('2. Progress', [`${dropped.filter((m) => m.role === 'assistant').length} earlier turns summarised.`]),
    section(
      '3. Tool calls made',
      calls.slice(-40).map((c) => `- ${c}`),
    ),
    section(
      '4. Key results',
      results.slice(-15).map((r) => `- ${r}`),
    ),
    section(
      '5. Errors and refusals',
      errors.slice(-10).map((e) => `- ${e}`),
    ),
    section(
      '6. Files examined',
      [...files].slice(0, 60).map((f) => `- ${f}`),
    ),
    section(
      '7. Reasoning notes',
      notes.slice(-8).map((n) => `- ${n}`),
    ),
    section('8. Next step', [
      'Continue the task; do not repeat calls listed above unless their result is needed again.',
    ]),
  ].join('\n\n');
}
