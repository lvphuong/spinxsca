import type { Classification, Disposition, FindingAssessment, ReconciliationState, Severity } from '@spinxsca/schemas';
import { SEVERITY_RANK, severityAtLeast } from '@spinxsca/schemas';
import { PRESENT_STATES } from './reconcile';

export interface PolicyOptions {
  failOnSeverity?: Severity;
  /** Trust AI downgrades and UNLIKELY classifications (`gate.trust_ai_downgrades`, default false). */
  trustAiDowngrades?: boolean;
  /**
   * Findings first reported by an AI role block only at or above this classification
   * (`gate.ai_discovered_min_classification`, default CONFIRMED; ADR-050).
   */
  aiDiscoveredMinClassification?: AiDiscoveredMinClassification;
  /** Gate only on findings that are new relative to the baseline (docs/architecture/05 section 4). */
  newFindingsOnly: boolean;
  /** Findings with an active human disposition (false positive, accepted risk, won't fix). */
  suppressed?: ReadonlySet<string>;
}

export type AiDiscoveredMinClassification = Extract<Classification, 'CONFIRMED' | 'POTENTIAL'>;

/** Options of `gateView`: both default to the untrusting Phase 5 posture. */
export interface GateViewOptions {
  trustAiDowngrades?: boolean;
  aiDiscoveredMinClassification?: AiDiscoveredMinClassification;
}

const CLASSIFICATION_RANK: Record<Classification, number> = {
  CONFIRMED: 3,
  POTENTIAL: 2,
  UNLIKELY: 1,
  NOT_EVALUATED: 0,
};

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
    const view = gateView(a, {
      trustAiDowngrades: options.trustAiDowngrades ?? false,
      ...(options.aiDiscoveredMinClassification
        ? { aiDiscoveredMinClassification: options.aiDiscoveredMinClassification }
        : {}),
    });
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
 * the severity is max(baseline, AI) and an AI UNLIKELY does not exempt the finding. A finding no
 * scanner reported (`discoveredBy: 'ai'`) is exempt until its classification reaches the configured
 * minimum, so a model's unvalidated word alone never blocks a release (ADR-050).
 */
export function gateView(
  a: Pick<FindingAssessment, 'classification' | 'severity' | 'severityBaseline'> &
    Partial<Pick<FindingAssessment, 'assessedBy' | 'discoveredBy'>>,
  options: boolean | GateViewOptions,
): { severity: Severity; exempt: boolean } {
  const opts: GateViewOptions = typeof options === 'boolean' ? { trustAiDowngrades: options } : options;
  const trustAiDowngrades = opts.trustAiDowngrades ?? false;
  const minimum = opts.aiDiscoveredMinClassification ?? 'CONFIRMED';
  if (a.discoveredBy === 'ai' && CLASSIFICATION_RANK[a.classification] < CLASSIFICATION_RANK[minimum]) {
    return { severity: a.severity, exempt: true };
  }
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
