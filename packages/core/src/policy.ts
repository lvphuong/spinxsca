import type { Disposition, FindingAssessment, ReconciliationState, Severity } from '@spinxsca/schemas';
import { severityAtLeast } from '@spinxsca/schemas';
import { PRESENT_STATES } from './reconcile';

export interface PolicyOptions {
  failOnSeverity?: Severity;
  /** Gate only on findings that are new relative to the baseline (docs/architecture/05 section 4). */
  newFindingsOnly: boolean;
  /** Findings with an active human disposition (false positive, accepted risk, won't fix). */
  suppressed?: ReadonlySet<string>;
}

export interface PolicyResult {
  passed: boolean;
  evaluated: boolean;
  violations: FindingAssessment[];
}

const NEW_STATES: ReadonlySet<ReconciliationState> = new Set(['NEW', 'REOPENED', 'NEEDS_RECONCILIATION']);

/**
 * CI gate. Findings the AI validator classified UNLIKELY (source-backed counterevidence) and
 * findings with an active disposition do not block; everything else at or above the threshold does.
 */
export function evaluatePolicy(assessments: readonly FindingAssessment[], options: PolicyOptions): PolicyResult {
  const threshold = options.failOnSeverity;
  if (!threshold) return { passed: true, evaluated: false, violations: [] };
  const gated = options.newFindingsOnly ? NEW_STATES : PRESENT_STATES;
  const violations = assessments.filter(
    (a) =>
      gated.has(a.reconciliationState) &&
      a.classification !== 'UNLIKELY' &&
      !options.suppressed?.has(a.findingId) &&
      severityAtLeast(a.severity, threshold),
  );
  return { passed: violations.length === 0, evaluated: true, violations };
}

/** Latest non-expired disposition per finding. */
export function activeDispositions(dispositions: readonly Disposition[], now: Date): Map<string, Disposition> {
  const active = new Map<string, Disposition>();
  const sorted = [...dispositions].sort((a, b) => a.decidedAt.localeCompare(b.decidedAt));
  for (const d of sorted) {
    if (d.expiresAt && new Date(d.expiresAt) <= now) {
      active.delete(d.findingId);
      continue;
    }
    active.set(d.findingId, d);
  }
  return active;
}
