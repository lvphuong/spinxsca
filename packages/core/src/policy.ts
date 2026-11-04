import type { Disposition, FindingAssessment, ReconciliationState, Severity } from '@spinxsca/schemas';
import { SEVERITY_RANK, severityAtLeast } from '@spinxsca/schemas';
import { PRESENT_STATES } from './reconcile';

export interface PolicyOptions {
  failOnSeverity?: Severity;
  /** Trust AI downgrades and UNLIKELY classifications (`gate.trust_ai_downgrades`, default false). */
  trustAiDowngrades?: boolean;
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
 * CI gate. Findings with an active disposition do not block; everything else at or above the
 * threshold does. AI downgrades (lower severity, UNLIKELY) count only when `trustAiDowngrades` is
 * set; otherwise a human disposition is needed to clear a finding (ADR-041).
 */
export function evaluatePolicy(assessments: readonly FindingAssessment[], options: PolicyOptions): PolicyResult {
  const threshold = options.failOnSeverity;
  if (!threshold) return { passed: true, evaluated: false, violations: [] };
  const gated = options.newFindingsOnly ? NEW_STATES : PRESENT_STATES;
  const violations = assessments.filter((a) => {
    if (!gated.has(a.reconciliationState) || options.suppressed?.has(a.findingId)) return false;
    const view = gateView(a, options.trustAiDowngrades ?? false);
    return !view.exempt && severityAtLeast(view.severity, threshold);
  });
  return { passed: violations.length === 0, evaluated: true, violations };
}

/** True when an assessment's conclusion came from a model (explain, investigation, autonomous review). */
export function isAiAssessment(a: Partial<Pick<FindingAssessment, 'assessedBy'>>): boolean {
  return a.assessedBy?.startsWith('agent:') ?? false;
}

/**
 * What the CI policy and the release gate act on. Untrusted AI downgrades fall back to the baseline:
 * the severity is max(baseline, AI) and an AI UNLIKELY does not exempt the finding.
 */
export function gateView(
  a: Pick<FindingAssessment, 'classification' | 'severity' | 'severityBaseline'> &
    Partial<Pick<FindingAssessment, 'assessedBy'>>,
  trustAiDowngrades: boolean,
): { severity: Severity; exempt: boolean } {
  const unlikely = a.classification === 'UNLIKELY';
  if (trustAiDowngrades || !isAiAssessment(a)) return { severity: a.severity, exempt: unlikely };
  const baseline = a.severityBaseline;
  const severity = baseline && SEVERITY_RANK[baseline] > SEVERITY_RANK[a.severity] ? baseline : a.severity;
  return { severity, exempt: false };
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
