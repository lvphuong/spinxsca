import type { JournalEntry } from '@spinxsca/schemas';

/** Compact rendering of the journal for a prompt (newest last, bounded). */
export function renderJournal(
  entries: readonly JournalEntry[],
  options: { limit?: number; maxChars?: number } = {},
): string {
  const limit = options.limit ?? 60;
  const maxChars = options.maxChars ?? 12_000;
  const lines: string[] = [];
  let size = 0;
  for (const e of [...entries].slice(-limit).reverse()) {
    const refs = e.refs.map((r) => `${r.path}:${r.startLine}`).join(', ');
    const line = `[${e.seq}] ${e.kind} ${e.author}${e.handles.length ? ` (${e.handles.join(', ')})` : ''}: ${e.text.replace(/\s+/g, ' ').slice(0, 600)}${refs ? ` [${refs}]` : ''}`;
    if (size + line.length > maxChars) break;
    lines.push(line);
    size += line.length + 1;
  }
  return lines.reverse().join('\n');
}
