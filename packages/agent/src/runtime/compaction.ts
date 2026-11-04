import type { ContentBlock, Message } from '../llm/types';

export interface CompactionOptions {
  /** Compact the outbound view once the transcript is estimated above this many tokens. */
  thresholdTokens: number;
  /** Most recent assistant turns kept verbatim (with their tool results). */
  keepTurns: number;
  /** Optional model-written summary; the deterministic summary is used when absent or failing. */
  summarize?: (dropped: readonly Message[]) => Promise<string>;
}

export const DEFAULT_COMPACTION: CompactionOptions = { thresholdTokens: 120_000, keepTurns: 6 };

/** Rough token estimate (4 characters per token) used only to decide when to compact. */
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

/**
 * Outbound-only compaction (ADR-042): the durable transcript is never rewritten. The request sent to
 * the model keeps the original prompt verbatim, replaces the middle with an eight-section summary and
 * keeps the last turns intact, starting at an assistant turn so no tool_result loses its tool_use.
 */
export async function compactView(messages: readonly Message[], options: CompactionOptions): Promise<Message[]> {
  if (estimateTokens(messages) <= options.thresholdTokens) return [...messages];
  const assistantIdx = messages.map((m, i) => (m.role === 'assistant' ? i : -1)).filter((i) => i > 0);
  if (assistantIdx.length <= options.keepTurns) return [...messages];
  const cut = assistantIdx[assistantIdx.length - options.keepTurns] as number;
  const dropped = messages.slice(1, cut);
  let summary: string;
  try {
    summary = options.summarize ? await options.summarize(dropped) : deterministicSummary(dropped);
  } catch {
    summary = deterministicSummary(dropped);
  }
  const prompt = messages[0] as Message;
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
  return [head, ...messages.slice(cut)];
}

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
