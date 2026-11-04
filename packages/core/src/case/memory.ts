import type { Digest, MemoryEntry, MemoryKind } from '@spinxsca/schemas';

/** Share of changed files above which architecture notes are considered stale. */
export const ARCHITECTURE_CHURN_LIMIT = 0.3;

/**
 * Status a new memory entry gets (ADR-046): host-written verdict caches and human dispositions are
 * active; architecture notes are active but untrusted and invalidated by churn; lessons and
 * conventions written by agents change future behaviour, so they wait for a human.
 */
export function initialMemoryStatus(kind: MemoryKind, writtenBy: 'host' | 'human' | 'agent'): MemoryEntry['status'] {
  if (writtenBy === 'human') return 'active';
  if (kind === 'LESSON' || kind === 'CONVENTION' || kind === 'DISPOSITION')
    return writtenBy === 'host' ? 'active' : 'proposed';
  return 'active';
}

/** Entries to invalidate for the current snapshot. */
export function memoryInvalidations(
  entries: readonly MemoryEntry[],
  ctx: { changedFileRatio: number; digestOf: (path: string) => Digest | undefined },
): Array<{ memoryId: string; reason: string }> {
  const out: Array<{ memoryId: string; reason: string }> = [];
  for (const e of entries) {
    if (e.status === 'invalidated') continue;
    if (e.kind === 'ARCHITECTURE' && ctx.changedFileRatio > ARCHITECTURE_CHURN_LIMIT) {
      out.push({ memoryId: e.memoryId, reason: `${Math.round(ctx.changedFileRatio * 100)}% of files changed` });
      continue;
    }
    for (const [path, digest] of Object.entries(e.fileDigests ?? {})) {
      if (ctx.digestOf(path) !== digest) {
        out.push({ memoryId: e.memoryId, reason: `${path} changed` });
        break;
      }
    }
  }
  return out;
}

/** A still-valid cached verdict for a finding fingerprint. */
export function cachedVerdict(
  entries: readonly MemoryEntry[],
  fingerprint: string,
  digestOf: (path: string) => Digest | undefined,
): MemoryEntry | undefined {
  return entries.find(
    (e) =>
      e.kind === 'VERDICT_CACHE' &&
      e.status === 'active' &&
      e.key === fingerprint &&
      Object.entries(e.fileDigests ?? {}).every(([path, digest]) => digestOf(path) === digest),
  );
}

/**
 * Memory for prompts. Only active entries; wrapped as untrusted data because architecture notes
 * were written by agents that read repository content.
 */
export function renderMemory(entries: readonly MemoryEntry[], maxChars = 6000): string {
  const active = entries.filter((e) => e.status === 'active' && e.kind !== 'VERDICT_CACHE');
  if (active.length === 0) return '';
  const lines: string[] = [];
  let size = 0;
  for (const e of active) {
    const line = `- [${e.kind.toLowerCase()}] ${e.text.replace(/\s+/g, ' ').slice(0, 500)}`;
    if (size + line.length > maxChars) break;
    lines.push(line);
    size += line.length;
  }
  return ['<project_memory untrusted="true">', ...lines, '</project_memory>'].join('\n');
}
