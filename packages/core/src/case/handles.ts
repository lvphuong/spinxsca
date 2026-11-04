import type { CaseHandle, RunRef } from '@spinxsca/schemas';
import { sha256, stableStringify } from '../ids';
import type { CandidateDraft } from '../ports';

/**
 * Identity of a draft inside one scan, before reconciliation assigns finding ids. Verdicts reach
 * findings only through this reference, so a model can never address a host identifier.
 */
export function draftRef(
  d: Pick<CandidateDraft, 'scanner' | 'ruleId' | 'category' | 'locations'> &
    Partial<Pick<CandidateDraft, 'vulnerabilityIds' | 'package'>>,
): string {
  const p = d.locations[0];
  const base = [d.scanner, d.ruleId, p?.path ?? '', p?.startLine ?? 0, p?.endLine ?? 0, d.category];
  // Dependency drafts share rule and location per package: the advisory and package tell them apart.
  const dependency =
    d.vulnerabilityIds?.length || d.package ? [[...(d.vulnerabilityIds ?? [])].sort(), d.package?.purl ?? ''] : [];
  return sha256(stableStringify([...base, ...dependency]));
}

/** Case-local handles CF-1, CF-2, … assigned in a stable order and persisted with the case. */
export class HandleTable {
  private readonly byRefMap = new Map<string, CaseHandle>();
  private readonly byHandleMap = new Map<string, CaseHandle>();
  private next = 1;

  constructor(
    readonly caseId: string,
    existing: readonly CaseHandle[] = [],
  ) {
    for (const h of existing) this.add(h);
  }

  private add(h: CaseHandle): void {
    this.byRefMap.set(h.draftRef, h);
    this.byHandleMap.set(h.handle, h);
    const n = Number(h.handle.slice(3));
    if (n >= this.next) this.next = n + 1;
  }

  /** Returns the existing handle of the draft or assigns the next one. */
  assign(
    draft: CandidateDraft,
    origin: CaseHandle['origin'],
    producer?: RunRef,
  ): { handle: CaseHandle; created: boolean } {
    const ref = draftRef(draft);
    const existing = this.byRefMap.get(ref);
    if (existing) return { handle: existing, created: false };
    const p = draft.locations[0];
    const handle: CaseHandle = {
      caseId: this.caseId,
      handle: `CF-${this.next}`,
      draftRef: ref,
      origin,
      ...(producer ? { producer } : {}),
      scanner: draft.scanner,
      ruleId: draft.ruleId,
      category: draft.category,
      title: draft.title,
      severity: draft.severityHint,
      path: p?.path ?? '',
      startLine: p?.startLine ?? 1,
      ...(draft.package ? { packagePurl: draft.package.purl } : {}),
      vulnerabilityIds: draft.vulnerabilityIds ?? [],
      ...(origin === 'agent' ? { draft } : {}),
    };
    this.add(handle);
    return { handle, created: true };
  }

  get(handle: string): CaseHandle | undefined {
    return this.byHandleMap.get(handle);
  }

  byRef(ref: string): CaseHandle | undefined {
    return this.byRefMap.get(ref);
  }

  all(): CaseHandle[] {
    return [...this.byHandleMap.values()].sort((a, b) => Number(a.handle.slice(3)) - Number(b.handle.slice(3)));
  }
}
