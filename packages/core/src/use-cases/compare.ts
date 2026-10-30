import type { ChangeCause, ReconciliationState, ScanRun, Severity } from '@spinxsca/schemas';
import { SpinxscaError } from '../errors';
import { manifestChangeCauses } from '../manifest';
import type { ScanRepository } from '../ports';
import { PRESENT_STATES } from '../reconcile';

export type ComparisonValidity = 'IDENTICAL_INPUTS' | 'SOURCE_DELTA' | 'INTELLIGENCE_DELTA' | 'MIXED_INPUT_CHANGES';
export type Transition = 'introduced' | 'fixed' | 'persisting' | 'not-reevaluated' | 'absent';

export interface ComparisonEntry {
  findingId: string;
  title: string;
  category: string;
  severity: Severity;
  from?: ReconciliationState;
  to?: ReconciliationState;
  transition: Transition;
  causes: ChangeCause[];
}

export interface ScanComparison {
  from: ScanRun;
  to: ScanRun;
  /** Which inputs differ, so a new finding is not misread as a code regression (docs/thiet-ke.md section 39). */
  validity: ComparisonValidity;
  inputChanges: ChangeCause[];
  entries: ComparisonEntry[];
  summary: Record<Transition, number>;
}

const INTELLIGENCE: ReadonlySet<ChangeCause> = new Set([
  'RULE_ADDED',
  'RULE_UPDATED',
  'SCANNER_UPGRADED',
  'ADVISORY_UPDATED',
]);

export async function compareScans(repo: ScanRepository, fromId: string, toId: string): Promise<ScanComparison> {
  const [from, to] = await Promise.all([repo.getScan(fromId), repo.getScan(toId)]);
  if (!from) throw new SpinxscaError(`scan ${fromId} not found`, 'NOT_FOUND');
  if (!to) throw new SpinxscaError(`scan ${toId} not found`, 'NOT_FOUND');
  if (from.projectId !== to.projectId) throw new SpinxscaError('scans belong to different projects', 'INVALID');

  const inputChanges = manifestChangeCauses(from.manifest, to.manifest).filter((c) => c !== 'UNKNOWN');
  const code = inputChanges.includes('CODE_CHANGE');
  const intel = inputChanges.some((c) => INTELLIGENCE.has(c));
  const validity: ComparisonValidity =
    code && intel ? 'MIXED_INPUT_CHANGES' : code ? 'SOURCE_DELTA' : intel ? 'INTELLIGENCE_DELTA' : 'IDENTICAL_INPUTS';

  const [fromAssessments, toAssessments] = await Promise.all([
    repo.listAssessments(fromId),
    repo.listAssessments(toId),
  ]);
  const fromBy = new Map(fromAssessments.map((a) => [a.findingId, a]));
  const toBy = new Map(toAssessments.map((a) => [a.findingId, a]));
  const ids = [...new Set([...fromBy.keys(), ...toBy.keys()])].sort();
  const entries: ComparisonEntry[] = [];
  for (const id of ids) {
    const a = fromBy.get(id);
    const b = toBy.get(id);
    const finding = await repo.getFinding(id);
    const fromPresent = a
      ? PRESENT_STATES.has(a.reconciliationState) || a.reconciliationState === 'NOT_REEVALUATED'
      : false;
    const toPresent = b ? PRESENT_STATES.has(b.reconciliationState) : false;
    let transition: Transition;
    if (b?.reconciliationState === 'NOT_REEVALUATED') transition = 'not-reevaluated';
    else if (fromPresent && toPresent) transition = 'persisting';
    else if (!fromPresent && toPresent) transition = 'introduced';
    else if (fromPresent && !toPresent) transition = 'fixed';
    else transition = 'absent';
    if (transition === 'absent') continue;
    entries.push({
      findingId: id,
      title: finding?.title ?? id,
      category: finding?.category ?? 'OTHER',
      severity: (b ?? a)?.severity ?? 'INFO',
      ...(a ? { from: a.reconciliationState } : {}),
      ...(b ? { to: b.reconciliationState } : {}),
      transition,
      causes: b?.changeCauses ?? [],
    });
  }
  const summary: Record<Transition, number> = {
    introduced: 0,
    fixed: 0,
    persisting: 0,
    'not-reevaluated': 0,
    absent: 0,
  };
  for (const e of entries) summary[e.transition]++;
  return { from, to, validity, inputChanges, entries, summary };
}
