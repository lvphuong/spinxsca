import { z } from 'zod';
import { Confidence, Digest, Severity, Timestamp } from './common';
import { Applicability, AttackPath, Classification, PocResult, VerificationLevel } from './finding';
import { AutonomyMode, PolicyLayer, PolicyOutcome, RiskClass } from './governance';

/**
 * Autonomous review case (ADR-044): one governed review of one scan. The host owns the board, the
 * objectives, the journal, the ledger and every verdict that reaches a finding; agents propose.
 */
export const CaseStatus = z.enum([
  'RUNNING',
  /** Waiting for a human in the inbox; resumed by CASE_RESUME. */
  'PARKED',
  /** Paused by an operator (ADR-052); interrupted work stays in progress and resumes with CASE_RESUME. */
  'PAUSED',
  'CONVERGED',
  'STAGNATED',
  'BUDGET_EXHAUSTED',
  'CANCELLED',
  'FAILED',
]);
export type CaseStatus = z.infer<typeof CaseStatus>;

export const ReviewCase = z.object({
  caseId: z.string(),
  projectId: z.string(),
  scanId: z.string(),
  snapshotId: z.string(),
  /** The operator's request, verbatim (shown to the reviewer model as the goal). */
  goal: z.string(),
  mode: AutonomyMode,
  attended: z.boolean(),
  status: CaseStatus,
  stopReason: z.string().optional(),
  round: z.number().int().nonnegative(),
  /** Digest of the autonomy policy, personas, playbooks and toolbox in force. */
  policyDigest: Digest,
  createdAt: Timestamp,
  updatedAt: Timestamp,
  completedAt: Timestamp.optional(),
});
export type ReviewCase = z.infer<typeof ReviewCase>;

export const ObjectiveKind = z.enum([
  /** Every mandatory work item is done. */
  'MANDATORY_DONE',
  /** Every finding handle has a verdict other than UNREVIEWED. */
  'ALL_TRIAGED',
  /** Every TRUE_POSITIVE cites evidence; HIGH and above also carry an attack path. */
  'CONFIRMED_HAVE_EVIDENCE',
  /** Every vulnerable package has an applicability decision. */
  'DEPENDENCIES_ASSESSED',
  /** No coverage check is NOT_RUN. */
  'COVERAGE_RECORDED',
  /** Runtime-verifiable TRUE_POSITIVEs at or above a severity have a PoC outcome (L3 enabled). */
  'L3_ATTEMPTED',
  /** Operator objective met when its linked work item is done with evidence. */
  'CUSTOM',
  /** Every invariant of the ground truth has a PASS/FAIL/UNKNOWN result. */
  'INVARIANTS_CHECKED',
  /** Every variant-family member has a hunt-log verdict. */
  'FAMILIES_SWEPT',
]);
export type ObjectiveKind = z.infer<typeof ObjectiveKind>;

export const ObjectiveStatus = z.enum(['OPEN', 'MET', 'NOT_MET', 'WAIVED']);
export type ObjectiveStatus = z.infer<typeof ObjectiveStatus>;

export const Objective = z.object({
  objectiveId: z.string(),
  caseId: z.string(),
  kind: ObjectiveKind,
  title: z.string(),
  /** Parameters of the falsifiable criterion (e.g. { minSeverity: 'HIGH' }). */
  criteria: z.record(z.string(), z.unknown()).default({}),
  status: ObjectiveStatus,
  reason: z.string().optional(),
  evaluatedAt: Timestamp.optional(),
  waivedBy: z.string().optional(),
});
export type Objective = z.infer<typeof Objective>;

export const WorkItemKind = z.enum([
  'TRIAGE_FINDING',
  'DEPENDENCY_APPLICABILITY',
  'SECRETS_SWEEP',
  'IAC_REVIEW',
  'THREAT_PACKET',
  'BASELINE_AUDIT',
  'HYPOTHESIS',
  'VARIANT_HUNT',
  'EXPLOIT_POC',
  'REVIEW_POC',
  'FIX',
  'VERIFY_FIX',
  'DEDUPE',
  'REPORT',
  /** Phase 6 (ADR-049): ground truth first, then logic audits per resource group, then critic re-passes. */
  'RECON',
  'LOGIC_AUDIT',
  'COMPLETENESS_CRITIC',
]);
export type WorkItemKind = z.infer<typeof WorkItemKind>;

export const WorkItemStatus = z.enum(['todo', 'in_progress', 'blocked', 'review', 'done', 'cancelled']);
export type WorkItemStatus = z.infer<typeof WorkItemStatus>;

export const RunRef = z.object({ persona: z.string(), runId: z.string() });
export type RunRef = z.infer<typeof RunRef>;

export const WorkItem = z.object({
  itemId: z.string(),
  caseId: z.string(),
  kind: WorkItemKind,
  title: z.string(),
  description: z.string().default(''),
  status: WorkItemStatus,
  /** Seeded by the host conductor; cannot be cancelled by the lead. */
  mandatory: z.boolean(),
  persona: z.string(),
  /** Case-local finding handles this item is about (CF-n). */
  handles: z.array(z.string()).default([]),
  dependsOn: z.array(z.string()).default([]),
  /** For checks of another item (REVIEW_POC, VERIFY_FIX): the item being checked. */
  subjectItemId: z.string().optional(),
  producer: RunRef.optional(),
  verifier: RunRef.optional(),
  /** Validated deliverable of the producer. */
  result: z.unknown().optional(),
  blockedReason: z.string().optional(),
  createdBy: z.enum(['host', 'lead']),
  round: z.number().int().nonnegative(),
  attempts: z.number().int().nonnegative().default(0),
  createdAt: Timestamp,
  updatedAt: Timestamp,
});
export type WorkItem = z.infer<typeof WorkItem>;

export const SourceRef = z.object({
  path: z.string(),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
});
export type SourceRef = z.infer<typeof SourceRef>;

export const JournalKind = z.enum([
  'OBSERVATION',
  'HYPOTHESIS',
  'EVIDENCE',
  'DECISION',
  'GAP',
  'PROPOSAL',
  'VERDICT',
  'NOTE',
]);
export type JournalKind = z.infer<typeof JournalKind>;

/** Evidence journal (hash chained): what was observed and decided, with citations. */
export const JournalEntry = z.object({
  caseId: z.string(),
  seq: z.number().int().nonnegative(),
  kind: JournalKind,
  /** "host" or "<persona>/<runId>". */
  author: z.string(),
  itemId: z.string().optional(),
  handles: z.array(z.string()).default([]),
  text: z.string().max(8000),
  refs: z.array(SourceRef).default([]),
  data: z.record(z.string(), z.unknown()).optional(),
  at: Timestamp,
  prevHash: Digest,
  hash: Digest,
});
export type JournalEntry = z.infer<typeof JournalEntry>;

/** Coverage as a deliverable: every check the case owes has an outcome and a reason. */
export const CoverageCheck = z.object({
  caseId: z.string(),
  checkId: z.string(),
  title: z.string(),
  outcome: z.enum(['RAN', 'DEGRADED', 'NOT_RUN']),
  reason: z.string().optional(),
  at: Timestamp,
});
export type CoverageCheck = z.infer<typeof CoverageCheck>;

export const MemoryKind = z.enum(['DISPOSITION', 'VERDICT_CACHE', 'ARCHITECTURE', 'LESSON', 'CONVENTION']);
export type MemoryKind = z.infer<typeof MemoryKind>;

export const MemoryStatus = z.enum(['active', 'proposed', 'invalidated']);
export type MemoryStatus = z.infer<typeof MemoryStatus>;

/** Project memory (ADR-046). Agent-written entries stay `proposed` until a human promotes them. */
export const MemoryEntry = z.object({
  memoryId: z.string(),
  projectId: z.string(),
  kind: MemoryKind,
  status: MemoryStatus,
  /** Lookup key: a finding fingerprint for VERDICT_CACHE, a topic otherwise. */
  key: z.string(),
  text: z.string().max(4000),
  data: z.unknown().optional(),
  /** Files the entry depends on; a changed digest invalidates it. */
  fileDigests: z.record(z.string(), Digest).optional(),
  sourceCaseId: z.string().optional(),
  createdBy: z.string(),
  createdAt: Timestamp,
  updatedAt: Timestamp,
  statusReason: z.string().optional(),
});
export type MemoryEntry = z.infer<typeof MemoryEntry>;

export const CaseLedger = z.object({
  caseId: z.string(),
  costUsd: z.number().nonnegative(),
  inputTokens: z.number().int().nonnegative(),
  outputTokens: z.number().int().nonnegative(),
  modelCalls: z.number().int().nonnegative(),
  sandboxRuns: z.number().int().nonnegative(),
  sandboxCpuSec: z.number().nonnegative(),
  /** Validation (PoC) runs per finding handle. */
  validationRuns: z.record(z.string(), z.number().int().nonnegative()),
  /** True when a model without a known price was used (cost is a lower bound). */
  unpriced: z.boolean(),
  updatedAt: Timestamp,
});
export type CaseLedger = z.infer<typeof CaseLedger>;

export const ToolCallStatus = z.enum([
  'PROPOSED',
  'ALLOWED',
  'DENIED',
  'PARKED',
  'RUNNING',
  'FINISHED',
  'FAILED',
  'CANCELLED',
]);
export type ToolCallStatus = z.infer<typeof ToolCallStatus>;

/** Durable record of one tool call, so a resumed run never repeats a side effect. */
export const ToolCallRecord = z.object({
  caseId: z.string(),
  toolCallId: z.string(),
  agentRunId: z.string(),
  itemId: z.string().optional(),
  tool: z.string(),
  risk: RiskClass,
  status: ToolCallStatus,
  /** Scrubbed input, kept for replay after an approval. */
  input: z.unknown(),
  argsDigest: Digest,
  decision: z.object({ outcome: PolicyOutcome, layer: PolicyLayer, rule: z.string() }).optional(),
  approvalId: z.string().optional(),
  /** Scrubbed, capped output returned to the model. */
  output: z.string().optional(),
  outputDigest: Digest.optional(),
  isError: z.boolean().optional(),
  createdAt: Timestamp,
  updatedAt: Timestamp,
});
export type ToolCallRecord = z.infer<typeof ToolCallRecord>;

/** One durable step of an agent session (transcript checkpoint). */
export const AgentStepRecord = z.object({
  agentRunId: z.string(),
  caseId: z.string(),
  index: z.number().int().nonnegative(),
  kind: z.enum(['prompt', 'turn', 'results']),
  /** Provider-neutral content blocks (validated by @spinxsca/agent). */
  content: z.array(z.unknown()),
  model: z.string().optional(),
  stopReason: z.string().optional(),
  usage: z
    .object({
      inputTokens: z.number().int().nonnegative(),
      outputTokens: z.number().int().nonnegative(),
      cacheReadTokens: z.number().int().nonnegative(),
      cacheWriteTokens: z.number().int().nonnegative(),
    })
    .optional(),
  at: Timestamp,
});
export type AgentStepRecord = z.infer<typeof AgentStepRecord>;

/** Case-local handle of a finding candidate, so models never see or invent host identifiers. */
export const CaseHandle = z.object({
  caseId: z.string(),
  handle: z.string().regex(/^CF-\d+$/),
  /** sha256(scanner, ruleId, path, startLine, endLine, category) of the draft. */
  draftRef: z.string(),
  origin: z.enum(['scanner', 'agent']),
  /** Run that produced an agent draft; triage must be done by another run and persona. */
  producer: RunRef.optional(),
  scanner: z.string(),
  ruleId: z.string(),
  category: z.string(),
  title: z.string(),
  severity: Severity,
  path: z.string(),
  startLine: z.number().int().positive(),
  /** Dependency findings. */
  packagePurl: z.string().optional(),
  vulnerabilityIds: z.array(z.string()).default([]),
  /** Full draft of agent and history findings, needed to report them after a resume. */
  draft: z.unknown().optional(),
});
export type CaseHandle = z.infer<typeof CaseHandle>;

/** The case's conclusion about one handle; applied to the finding assessment before commit. */
export const CaseVerdict = z.object({
  caseId: z.string(),
  handle: z.string(),
  verdict: z.enum(['TRUE_POSITIVE', 'FALSE_POSITIVE', 'BLOCKED', 'UNREVIEWED']),
  classification: Classification,
  severity: Severity.optional(),
  confidence: Confidence,
  verificationLevel: VerificationLevel,
  rationale: z.string().max(4000),
  counterevidence: z.array(z.string().max(600)).default([]),
  /** FALSE_POSITIVE only: why the tool fired (pattern without a source, sanitized, test code, ...). */
  noiseReason: z.string().max(600).optional(),
  evidence: z.array(SourceRef.extend({ note: z.string().max(600).optional() })).default([]),
  attackPath: AttackPath.optional(),
  applicability: Applicability.optional(),
  poc: PocResult.optional(),
  producer: RunRef.optional(),
  validator: RunRef.optional(),
  at: Timestamp,
});
export type CaseVerdict = z.infer<typeof CaseVerdict>;

export const AutonomyModeChoice = z.enum(['observe', 'supervised', 'autonomous']);

/**
 * Options an operator chooses when starting a review (ADR-052). They can only narrow what the
 * server's configuration allows: a lower budget, fewer rounds, a stricter autonomy mode, fewer
 * scanners. Asking for proofs of concept only seeds the work; the policy engine still decides
 * whether each run needs a human.
 */
export const ReviewRunOptions = z.strictObject({
  mode: AutonomyModeChoice.optional(),
  maxCostUsd: z.number().positive().max(10_000).optional(),
  maxRounds: z.number().int().min(1).max(100).optional(),
  maxWallClockMin: z
    .number()
    .int()
    .min(1)
    .max(24 * 60)
    .optional(),
  /** Seed sandboxed proofs of concept for confirmed runtime-verifiable findings. */
  l3: z.boolean().optional(),
  /** Recon-first logic analysis (ADR-049). */
  recon: z.boolean().optional(),
  criticPasses: z.number().int().min(0).max(2).optional(),
  /** Run only these scanners (ids as reported by the server). */
  scanners: z
    .array(z.string().regex(/^[a-z][a-z0-9-]{1,40}$/))
    .min(1)
    .max(10)
    .optional(),
  /** Intended behaviours not to report (operator context, ADR-051). */
  acceptedRisks: z.array(z.string().min(10).max(600)).max(30).optional(),
});
export type ReviewRunOptions = z.infer<typeof ReviewRunOptions>;

/** What the server allows and uses when a review sets no option (`GET /v1/review-options`). */
export interface ReviewDefaults {
  /** False when AI is not configured on the server: reviews cannot run. */
  available: boolean;
  reason?: string;
  mode: z.infer<typeof AutonomyModeChoice>;
  maxCostUsd: number;
  maxRounds: number;
  maxWallClockMin: number;
  l3: boolean;
  recon: boolean;
  criticPasses: number;
  scanners: string[];
  provider?: string;
  model?: string;
}
