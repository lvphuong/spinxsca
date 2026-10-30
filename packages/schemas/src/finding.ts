import { z } from 'zod';
import { Confidence, FingerprintAnchor, Location, Severity, Timestamp } from './common';
import { VulnIntel } from './intel';
import { Category, CweId } from './taxonomy';

/** Stable identity of a vulnerability across scans and revisions (ADR-004). */
export const Finding = z.object({
  findingId: z.string(),
  projectId: z.string(),
  seq: z.number().int().positive(),
  category: Category,
  ruleFamily: z.string(),
  title: z.string(),
  cwe: z.array(CweId),
  canonicalFingerprint: z.string(),
  fingerprintAlgorithm: z.string(),
  firstSeenScanId: z.string(),
  createdAt: Timestamp,
});
export type Finding = z.infer<typeof Finding>;

/** Where a finding appears in one snapshot (ADR-005). */
export const FindingOccurrence = z.object({
  occurrenceId: z.string(),
  findingId: z.string(),
  scanId: z.string(),
  snapshotId: z.string(),
  locations: z.array(Location).min(1),
  fingerprint: z.string(),
  anchor: FingerprintAnchor,
  ruleIds: z.array(z.string()).min(1),
  candidateIds: z.array(z.string()).min(1),
  evidenceIds: z.array(z.string()),
});
export type FindingOccurrence = z.infer<typeof FindingOccurrence>;

export const ReconciliationState = z.enum([
  'NEW',
  'EXISTING',
  'REOPENED',
  'RESOLVED',
  'NOT_REEVALUATED',
  'NEEDS_RECONCILIATION',
]);
export type ReconciliationState = z.infer<typeof ReconciliationState>;

export const Classification = z.enum(['CONFIRMED', 'POTENTIAL', 'UNLIKELY', 'NOT_EVALUATED']);
export const Exploitability = z.enum(['CONFIRMED', 'POTENTIAL', 'UNLIKELY', 'UNKNOWN']);
export const VerificationLevel = z.enum(['L1_STATIC', 'L2_CONTEXT', 'L3_CONTROLLED']);

export const ChangeCause = z.enum([
  'CODE_CHANGE',
  'DEPENDENCY_CHANGE',
  'NEW_ADVISORY',
  'ADVISORY_UPDATED',
  'RULE_ADDED',
  'RULE_UPDATED',
  'SCANNER_UPGRADED',
  'AI_REASSESSMENT',
  'COVERAGE_CHANGE',
  'FIRST_SCAN',
  'UNKNOWN',
]);
export type ChangeCause = z.infer<typeof ChangeCause>;

export const AttackPath = z.object({
  attacker: z.string().optional(),
  entryPoint: z.string().optional(),
  source: z.string().optional(),
  sink: z.string().optional(),
  preconditions: z.array(z.string()).default([]),
  controls: z.array(z.string()).default([]),
});

/** The conclusion one scan reached about one finding. Never overwritten. */
export const FindingAssessment = z.object({
  assessmentId: z.string(),
  findingId: z.string(),
  scanId: z.string(),
  /** Absent when the finding no longer appears (RESOLVED / NOT_REEVALUATED). */
  occurrenceId: z.string().optional(),
  reconciliationState: ReconciliationState,
  classification: Classification,
  severity: Severity,
  confidence: Confidence,
  exploitability: Exploitability,
  verificationLevel: VerificationLevel,
  attackPath: AttackPath.optional(),
  evidenceIds: z.array(z.string()),
  counterevidence: z.array(z.string()),
  missingEvidence: z.array(z.string()),
  reasoningSummary: z.string(),
  changeCauses: z.array(ChangeCause),
  /** Dependency findings: KEV / EPSS / CVSS from the scan's knowledge base snapshot. */
  intel: VulnIntel.optional(),
  assessedBy: z.string(),
  assessedAt: Timestamp,
});
export type FindingAssessment = z.infer<typeof FindingAssessment>;

/** Human decisions are kept separate from assessments. */
export const Disposition = z.object({
  dispositionId: z.string(),
  findingId: z.string(),
  kind: z.enum(['FALSE_POSITIVE', 'ACCEPTED_RISK', 'WONT_FIX', 'DUPLICATE_OF']),
  reason: z.string().min(1),
  duplicateOf: z.string().optional(),
  scope: z.object({ type: z.enum(['PROJECT', 'BRANCH', 'SNAPSHOT']), ref: z.string() }),
  expiresAt: Timestamp.optional(),
  decidedBy: z.string(),
  decidedAt: Timestamp,
});
export type Disposition = z.infer<typeof Disposition>;

export const MatchMethod = z.enum(['EXACT_FINGERPRINT', 'RELOCATED', 'NEAR', 'NONE']);
export type MatchMethod = z.infer<typeof MatchMethod>;

/** Audit trail of every reconciliation decision. */
export const FindingMatchEvent = z.object({
  eventId: z.string(),
  scanId: z.string(),
  candidateId: z.string().optional(),
  findingId: z.string(),
  method: MatchMethod,
  confidence: Confidence,
  decision: ReconciliationState,
  decidedBy: z.enum(['host', 'reviewer', 'human']),
  detail: z.string(),
  createdAt: Timestamp,
});
export type FindingMatchEvent = z.infer<typeof FindingMatchEvent>;
