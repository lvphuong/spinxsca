import type { CaseHandle } from '@spinxsca/schemas';

/**
 * Deterministic duplicate suggestions (ADR-044): handles of the same category within a few lines of
 * each other in one file. Only a grouping hint for prompts and reports; finding identity is decided
 * by reconciliation, never here.
 */
export function duplicateGroups(handles: readonly CaseHandle[], window = 3): string[][] {
  const groups: string[][] = [];
  const byKey = new Map<string, CaseHandle[]>();
  for (const h of handles) {
    const key = `${h.category}|${h.path}`;
    byKey.set(key, [...(byKey.get(key) ?? []), h]);
  }
  for (const list of byKey.values()) {
    const sorted = [...list].sort((a, b) => a.startLine - b.startLine);
    let current: CaseHandle[] = [];
    for (const h of sorted) {
      const last = current.at(-1);
      if (last && h.startLine - last.startLine <= window) current.push(h);
      else {
        if (current.length > 1) groups.push(current.map((x) => x.handle));
        current = [h];
      }
    }
    if (current.length > 1) groups.push(current.map((x) => x.handle));
  }
  return groups;
}
