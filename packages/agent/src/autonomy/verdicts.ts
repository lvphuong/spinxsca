import type { CaseVerdict, ReachabilityLevel, RunRef } from '@spinxsca/schemas';
import type { ApplicabilityDeliverable, TriageDeliverable } from './deliverables';

export function triageVerdict(caseId: string, d: TriageDeliverable, validator: RunRef, at: string): CaseVerdict {
  const classification =
    d.verdict === 'FALSE_POSITIVE'
      ? 'UNLIKELY'
      : d.verdict === 'TRUE_POSITIVE' && d.confidence === 'HIGH' && d.evidence.length > 0
        ? 'CONFIRMED'
        : 'POTENTIAL';
  return {
    caseId,
    handle: d.handle,
    verdict: d.verdict,
    classification,
    severity: d.severity,
    confidence: d.confidence,
    verificationLevel: 'L2_CONTEXT',
    rationale: d.verdict === 'BLOCKED' ? `${d.rationale} Missing: ${d.missingEvidence.join('; ')}` : d.rationale,
    counterevidence: d.counterevidence,
    ...(d.noiseReason ? { noiseReason: d.noiseReason } : {}),
    evidence: d.evidence,
    ...(d.attackPath ? { attackPath: d.attackPath } : {}),
    validator,
    at,
  };
}

/**
 * Applicability verdict (VEX). Host rules: a vulnerable package used only in development or tests
 * and not called from project code is LOW whatever the advisory says; reachability measured by the
 * index is recorded next to the model's decision.
 */
export function applicabilityVerdict(
  caseId: string,
  d: ApplicabilityDeliverable,
  validator: RunRef,
  at: string,
  facts: { devOnly: boolean; reachability?: ReachabilityLevel },
): CaseVerdict {
  const reached = facts.reachability === 'CALLED' || facts.reachability === 'CALLED_FROM_ENTRYPOINT';
  const severity = d.status !== 'NOT_AFFECTED' && facts.devOnly && !reached ? 'LOW' : d.severity;
  const verdict =
    d.status === 'NOT_AFFECTED' ? 'FALSE_POSITIVE' : d.status === 'AFFECTED' ? 'TRUE_POSITIVE' : 'BLOCKED';
  return {
    caseId,
    handle: d.handle,
    verdict,
    classification:
      verdict === 'FALSE_POSITIVE' ? 'UNLIKELY' : verdict === 'TRUE_POSITIVE' && reached ? 'CONFIRMED' : 'POTENTIAL',
    severity,
    confidence: d.confidence,
    verificationLevel: 'L2_CONTEXT',
    rationale: d.rationale,
    counterevidence: d.status === 'NOT_AFFECTED' ? [d.rationale.slice(0, 600)] : [],
    ...(d.status === 'NOT_AFFECTED' && d.justification ? { noiseReason: `VEX: ${d.justification}` } : {}),
    evidence: d.evidence,
    applicability: {
      status: d.status,
      ...(d.justification ? { justification: d.justification } : {}),
      ...(facts.reachability ? { reachability: facts.reachability } : {}),
      symbolSource: d.symbolSource,
      scope: facts.devOnly ? 'development' : 'runtime',
      detail: d.rationale.slice(0, 2000),
    },
    validator,
    at,
  };
}
