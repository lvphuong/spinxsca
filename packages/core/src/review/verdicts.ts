import type { CaseVerdict, FindingAssessment, FindingCandidate, Severity } from '@spinxsca/schemas';
import { SEVERITY_RANK } from '@spinxsca/schemas';
import { draftRef } from '../case/handles';
import type { ReconcileOutput } from '../reconcile';

const STRENGTH: Record<CaseVerdict['verdict'], number> = {
  TRUE_POSITIVE: 3,
  BLOCKED: 2,
  FALSE_POSITIVE: 1,
  UNREVIEWED: 0,
};

/** Picks the verdict that speaks for a finding when several of its candidates were judged. */
function strongest(verdicts: readonly CaseVerdict[]): CaseVerdict | undefined {
  return [...verdicts].sort(
    (a, b) =>
      STRENGTH[b.verdict] - STRENGTH[a.verdict] ||
      Number(b.poc?.outcome === 'CONFIRMED') - Number(a.poc?.outcome === 'CONFIRMED') ||
      b.at.localeCompare(a.at),
  )[0];
}

/**
 * Applies review-case verdicts to the assessments of this scan before they are committed (ADR-044),
 * so each finding keeps one assessment per scan. The scanner severity is kept as `severityBaseline`;
 * the gate decides whether an AI downgrade counts. L3 needs a host-decided CONFIRMED PoC.
 */
export function applyCaseVerdicts(
  result: ReconcileOutput,
  candidates: readonly FindingCandidate[],
  verdicts: ReadonlyArray<{ draftRef: string; verdict: CaseVerdict }>,
  assessedBy: string,
): number {
  if (verdicts.length === 0) return 0;
  const byRef = new Map<string, CaseVerdict[]>();
  for (const v of verdicts) byRef.set(v.draftRef, [...(byRef.get(v.draftRef) ?? []), v.verdict]);
  const refOfCandidate = new Map(
    candidates.map((c) => [
      c.candidateId,
      draftRef({
        scanner: c.scanner,
        ruleId: c.ruleId,
        category: c.category,
        locations: c.locations,
        ...(c.vulnerabilityIds ? { vulnerabilityIds: c.vulnerabilityIds } : {}),
        ...(c.package ? { package: c.package } : {}),
      }),
    ]),
  );
  const occurrences = new Map(result.occurrences.map((o) => [o.occurrenceId, o]));
  let applied = 0;
  result.assessments = result.assessments.map((a) => {
    const occurrence = a.occurrenceId ? occurrences.get(a.occurrenceId) : undefined;
    if (!occurrence) return a;
    const found = occurrence.candidateIds.flatMap((id) => byRef.get(refOfCandidate.get(id) ?? '') ?? []);
    const v = strongest(found);
    if (!v || v.verdict === 'UNREVIEWED') return a;
    applied++;
    return merge(a, v, assessedBy);
  });
  return applied;
}

function merge(a: FindingAssessment, v: CaseVerdict, assessedBy: string): FindingAssessment {
  const severity: Severity = v.severity ?? a.severity;
  const l3 = v.poc?.outcome === 'CONFIRMED';
  const classification =
    v.verdict === 'FALSE_POSITIVE'
      ? 'UNLIKELY'
      : v.verdict === 'BLOCKED'
        ? 'POTENTIAL'
        : l3
          ? 'CONFIRMED'
          : v.classification;
  return {
    ...a,
    classification,
    severity,
    severityBaseline: a.severityBaseline ?? a.severity,
    confidence: v.confidence,
    exploitability:
      classification === 'CONFIRMED' ? 'CONFIRMED' : classification === 'UNLIKELY' ? 'UNLIKELY' : 'POTENTIAL',
    verificationLevel: l3 ? 'L3_CONTROLLED' : 'L2_CONTEXT',
    ...(v.attackPath ? { attackPath: v.attackPath } : {}),
    counterevidence: v.counterevidence,
    missingEvidence: v.verdict === 'BLOCKED' ? [v.rationale.slice(0, 600)] : a.missingEvidence,
    reasoningSummary: `${v.rationale}${v.noiseReason ? ` Noise: ${v.noiseReason}` : ''}`.slice(0, 4000),
    ...(v.applicability ? { applicability: v.applicability } : {}),
    ...(v.poc ? { poc: v.poc } : {}),
    assessedBy,
  };
}

/** True when the verdict lowered the severity below the scanner's (shown in reports). */
export function isDowngrade(a: Pick<FindingAssessment, 'severity' | 'severityBaseline'>): boolean {
  return a.severityBaseline !== undefined && SEVERITY_RANK[a.severity] < SEVERITY_RANK[a.severityBaseline];
}
