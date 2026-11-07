import type { LlmProvider, Message } from '../llm/types';
import type { CompactionOptions } from './compaction';
import { contextBudgetFor } from './context-budget';

export const SUMMARY_HEADINGS = [
  '## Goal',
  '## Constraints',
  '## Progress',
  '## Decisions',
  '## Next steps',
  '## Files examined',
  '## Open checklist rows',
] as const;

/** Fallback system prompt when the caller has no prompt bundle (mirrors prompts/summarize.md). */
export const DEFAULT_SUMMARY_SYSTEM = [
  'You summarise the earlier part of a security review session so the same reviewer can continue with less context. Terse, factual, no advice, no code, no secrets (write <redacted>).',
  `Use exactly these headings, each on its own line, in this order:\n${SUMMARY_HEADINGS.join('\n')}`,
  'Under "Files examined" list one path per line. Under "Open checklist rows" list invariant ids and family members not yet accounted for. Keep it under 400 words.',
].join('\n\n');

/** Text the summariser sees: the reviewer's own words and tool calls, never tool output. */
export function summaryInput(dropped: readonly Message[], maxChars = 60_000): string {
  const parts: string[] = [];
  for (const m of dropped) {
    for (const b of m.content) {
      if (b.type === 'text' && m.role === 'assistant') parts.push(`assistant: ${b.text}`);
      else if (b.type === 'text') parts.push(`user: ${b.text.slice(0, 2_000)}`);
      else if (b.type === 'tool_use') parts.push(`call ${b.name}(${JSON.stringify(b.input).slice(0, 300)})`);
    }
  }
  const text = parts.join('\n');
  return text.length > maxChars ? `${text.slice(0, maxChars)}\n… (earlier turns omitted)` : text;
}

/** True when a summary carries every mandatory heading (the deterministic summary is used otherwise). */
export function validSummary(text: string): boolean {
  return SUMMARY_HEADINGS.every((h) => text.includes(h));
}

/**
 * Model-written compaction summary (ADR-056): same fixed template every time, scrubbed before the
 * model sees the transcript, rejected when a heading is missing so the deterministic summary wins.
 */
export function llmSummarizer(
  provider: () => LlmProvider,
  options: { system: string; scrub?: (text: string) => string; maxTokens?: number } = { system: '' },
): NonNullable<CompactionOptions['summarize']> {
  return async (dropped) => {
    const p = provider();
    const budget = contextBudgetFor(p.capabilities(), { maxOutputTokens: options.maxTokens ?? 2_000 });
    const raw = summaryInput(dropped, Math.min(60_000, Math.floor(budget.effective * 4 * 0.6)));
    const input = options.scrub ? options.scrub(raw) : raw;
    const result = await p.complete({
      system: options.system,
      messages: [
        {
          role: 'user',
          content: [{ type: 'text', text: `Summarise this session segment.\n\n<session>\n${input}\n</session>` }],
        },
      ],
      tools: [],
      maxTokens: Math.min(budget.maxOutput, options.maxTokens ?? 2_000),
      metadata: { role: 'summarize' },
    });
    const text = result.content
      .flatMap((b) => (b.type === 'text' ? [b.text] : []))
      .join('\n')
      .trim();
    if (!validSummary(text)) throw new Error('summary is missing mandatory headings');
    return text;
  };
}

/**
 * Collapses everything between the first message and the last `keepLastTurns` assistant turns into
 * one note (reactive path after a context-length error). Pairs stay intact: the cut is an assistant turn.
 */
export function collapseView(messages: readonly Message[], options: { keepLastTurns?: number } = {}): Message[] {
  const keep = options.keepLastTurns ?? 2;
  const assistantIdx = messages.map((m, i) => (m.role === 'assistant' ? i : -1)).filter((i) => i > 0);
  if (assistantIdx.length <= keep) return [...messages];
  const cut = assistantIdx[assistantIdx.length - keep] as number;
  const dropped = messages.slice(1, cut);
  const files = new Set<string>();
  for (const m of dropped)
    for (const b of m.content)
      if (b.type === 'tool_use') {
        const path = (b.input as { path?: unknown })?.path;
        if (typeof path === 'string') files.add(path);
      }
  const first = messages[0] as Message;
  return [
    {
      role: 'user',
      content: [
        ...first.content,
        {
          type: 'text',
          text: `<earlier_work_collapsed turns="${dropped.filter((m) => m.role === 'assistant').length}">\nThe request did not fit the model's context. ${dropped.length} earlier messages were removed; files already examined: ${[...files].slice(0, 60).join(', ') || '(none)'}. Re-read what you still need and continue.\n</earlier_work_collapsed>`,
        },
      ],
    },
    ...messages.slice(cut),
  ];
}
