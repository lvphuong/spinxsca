import type { AiFinding, AiFindingLite, InvestigationResult, InvestigationResultLite } from '@spinxsca/schemas';

/**
 * Lifts a lite finding (ADR-054) to the full contract. Fields a small model was not asked for get
 * explicit placeholders rather than guesses: the attacker is unspecified, proof obligations are
 * declared unenumerated, and confidence is capped at MEDIUM so the host never treats a lite claim
 * as proven.
 */
export function liftLiteFinding(f: AiFindingLite): AiFinding {
  return {
    category: f.category,
    cwe: f.cwe,
    title: f.title,
    summary: f.summary,
    confidence: f.confidence === 'HIGH' ? 'MEDIUM' : f.confidence,
    severity: f.severity,
    attacker: 'unspecified (lite submission)',
    invariantViolated: f.claim,
    claim: f.claim,
    preconditions: f.preconditions,
    capabilitiesGained: f.capabilitiesGained,
    proofObligations: ['not enumerated by a lite submission'],
    threatModelClass: 'real_bug',
    ...(f.invariantId ? { invariantId: f.invariantId } : {}),
    ...(f.familyId ? { familyId: f.familyId } : {}),
    locations: [
      {
        path: f.path,
        startLine: f.startLine,
        endLine: Math.max(f.endLine ?? f.startLine, f.startLine),
        role: 'primary',
      },
    ],
    evidence: f.evidence,
    counterevidence: [],
    remediation: f.remediation,
  };
}

export function liftLiteResult(r: InvestigationResultLite): InvestigationResult {
  return {
    findings: r.findings.map(liftLiteFinding),
    resolvedQuestions: [],
    reviewedFiles: r.reviewedFiles,
    deferred: r.deferred,
    invariantResults: r.invariantResults,
    variantLog: r.variantLog,
  };
}

/** Lite deliverables when the model cannot call tools natively or its window is small (ADR-054). */
export function useLiteDeliverables(caps: { toolMode: string; maxContext: number }): boolean {
  return caps.toolMode !== 'native' || caps.maxContext < 64_000;
}
