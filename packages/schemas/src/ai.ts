import { z } from 'zod';
import { Confidence, Severity, SourceSpan, Timestamp } from './common';
import { Category, CweId } from './taxonomy';

/**
 * Deliverable of the explain role (docs/architecture/03 section 2: validator-lite + risk assessor).
 * The model submits semantic content only; the host validates every location against the snapshot
 * and assigns identifiers (ADR-022).
 */
export const AiExplanation = z.strictObject({
  summary: z.string().min(1).max(3000).describe('Plain-language explanation of the issue for a developer'),
  classification: z
    .enum(['CONFIRMED', 'POTENTIAL', 'UNLIKELY'])
    .describe(
      'CONFIRMED: source evidence shows attacker-controlled data reaches the sink with no effective control. POTENTIAL: plausible but evidence is incomplete. UNLIKELY: source-backed counterevidence shows the issue is not exploitable.',
    ),
  severity: Severity.describe('Severity under the rubric; choose the lower tier when two are arguable'),
  severityRationale: z.string().min(1).max(1500),
  selfRefutationCheck: z
    .string()
    .min(1)
    .max(800)
    .describe('State whether anything in your own rationale contradicts the classification and severity'),
  confidence: Confidence,
  attackPath: z.strictObject({
    attacker: z.string().max(300),
    entryPoint: z.string().max(300),
    source: z.string().max(300),
    sink: z.string().max(300),
    preconditions: z.array(z.string().max(300)).max(10),
    controls: z.array(z.string().max(300)).max(10).describe('Security controls on the path and whether they hold'),
  }),
  evidence: z
    .array(
      z.strictObject({
        path: z.string().min(1),
        startLine: z.number().int().positive(),
        endLine: z.number().int().positive(),
        explanation: z.string().min(1).max(600),
      }),
    )
    .min(1)
    .max(12),
  counterevidence: z.array(z.string().max(600)).max(10),
  missingEvidence: z.array(z.string().max(600)).max(10),
  remediation: z.strictObject({
    strategy: z.string().min(1).max(600),
    steps: z.array(z.string().max(600)).min(1).max(10),
    example: z.string().max(4000).optional().describe('Short illustrative code, not a full patch'),
  }),
});
export type AiExplanation = z.infer<typeof AiExplanation>;

export const AiAnswer = z.strictObject({
  answer: z.string().min(1).max(8000).describe('Markdown answer grounded in the code you read'),
  citations: z
    .array(
      z.strictObject({
        path: z.string().min(1),
        startLine: z.number().int().positive(),
        endLine: z.number().int().positive(),
      }),
    )
    .max(20),
  confidence: Confidence,
});
export type AiAnswer = z.infer<typeof AiAnswer>;

export const AgentUsage = z.object({
  inputTokens: z.number().int().nonnegative(),
  outputTokens: z.number().int().nonnegative(),
  cacheReadTokens: z.number().int().nonnegative(),
  cacheWriteTokens: z.number().int().nonnegative(),
});

/** Audit record of one agent run (docs/architecture/03 section 8). No hidden reasoning is stored. */
export const AgentRunRecord = z.object({
  agentRunId: z.string(),
  role: z.enum([
    'explain',
    'ask',
    'planner',
    'investigator',
    'auditor',
    'remediation',
    // Autonomous review personas (ADR-044).
    'lead',
    'appsec',
    'dependency',
    'secrets',
    'iac',
    'validator',
    'verifier',
    'fixer',
    'exploit',
    'dedupe',
    'explore',
    'reviewer',
    // Phase 6 (ADR-049): recon extracts ground truth, logic audits walk it, critics re-check coverage.
    'recon',
    'logic',
    'critic',
    // Phase 7 (ADR-055): shard workers, the reducer over their claims, compaction summaries.
    'mapper',
    'reducer',
    'summarize',
  ]),
  scanId: z.string().optional(),
  caseId: z.string().optional(),
  workItemId: z.string().optional(),
  personaId: z.string().optional(),
  /** Sub-agent runs (explore) point at the run that spawned them. */
  parentRunId: z.string().optional(),
  findingId: z.string().optional(),
  /** Fingerprint of the occurrence that was explained, so a resumed scan can reuse the run. */
  subjectDigest: z.string().optional(),
  provider: z.string(),
  model: z.string(),
  modelsUsed: z.array(z.string()),
  promptBundleDigest: z.string(),
  status: z.enum(['COMPLETED', 'BUDGET_EXHAUSTED', 'REFUSED', 'FAILED', 'CANCELLED', 'RUNNING', 'SUSPENDED']),
  usage: AgentUsage,
  costUsd: z.number().nonnegative().optional(),
  output: z.unknown().optional(),
  error: z.string().optional(),
  refusalCategory: z.string().optional(),
  steps: z.array(
    z.object({
      index: z.number().int(),
      stopReason: z.string(),
      model: z.string(),
      toolCalls: z.array(
        z.object({
          name: z.string(),
          ok: z.boolean(),
          id: z.string().optional(),
          argsDigest: z.string().optional(),
          outputDigest: z.string().optional(),
          decision: z.string().optional(),
        }),
      ),
    }),
  ),
  startedAt: Timestamp,
  completedAt: Timestamp,
});
export type AgentRunRecord = z.infer<typeof AgentRunRecord>;

/** Threat model and investigation packets produced by the planner (docs/architecture/03 section 4). */
export const InvestigationPacket = z.strictObject({
  packetId: z.string().min(1).max(40),
  perspective: z.enum([
    'FORWARD_SOURCE_TO_SINK',
    'BACKWARD_SINK_TO_ATTACKER',
    'AUTHZ_AND_BUSINESS_LOGIC',
    'OPEN_ENDED',
  ]),
  attacker: z.string().min(1).max(200),
  protectedAsset: z.string().min(1).max(200),
  entryPoints: z
    .array(z.strictObject({ path: z.string(), line: z.number().int().positive(), label: z.string().max(200) }))
    .min(1)
    .max(8),
  expectedControls: z.array(z.string().max(200)).max(8),
  questions: z.array(z.string().min(1).max(300)).min(1).max(6),
});
export type InvestigationPacket = z.infer<typeof InvestigationPacket>;

export const ThreatModel = z.strictObject({
  summary: z
    .string()
    .min(1)
    .max(3000)
    .describe('Architecture: entry points, trust boundaries, data stores, auth mechanism'),
  trustBoundaries: z.array(z.string().max(300)).max(10),
  packets: z.array(InvestigationPacket).max(8),
  notes: z.array(z.string().max(300)).max(10).describe('Gaps: parts of the code you could not characterise'),
});
export type ThreatModel = z.infer<typeof ThreatModel>;

// ---------------------------------------------------------------------------------------------
// Ground truth (ADR-049, ported from Argo's recon stage): what the code is supposed to guarantee,
// extracted before any hunting so audits verify a closed checklist instead of searching open-ended.
// ---------------------------------------------------------------------------------------------

const invariantId = z.string().regex(/^INV-\d{1,3}$/);
const baselineId = z.string().regex(/^BL-\d{1,3}$/);
const familyId = z.string().regex(/^FAM-\d{1,3}$/);
const carveoutId = z.string().regex(/^CO-\d{1,3}$/);
const unknownId = z.string().regex(/^RQ-\d{1,3}$/);

/** A named security property that MUST hold at a location: the audit's PASS/FAIL checklist row. */
export const GroundTruthInvariant = z.strictObject({
  invariantId,
  location: SourceSpan,
  expected: z.string().min(1).max(400).describe("The property that must hold, in the project's own terms"),
  howToCheck: z.string().min(1).max(400).describe('What to read to decide PASS or FAIL'),
  /** Packets (standard level) or work-item slugs (deep level) that own this check. */
  packets: z.array(z.string().max(60)).max(8).default([]),
  familyId: familyId.optional(),
});
export type GroundTruthInvariant = z.infer<typeof GroundTruthInvariant>;

/** The one place a systemic pattern is done right; every sibling is diffed against it. */
export const BaselineReference = z.strictObject({
  baselineId,
  pattern: z.string().min(1).max(200),
  location: SourceSpan,
  whyCorrect: z.string().min(1).max(400),
});
export type BaselineReference = z.infer<typeof BaselineReference>;

/** A repeated shape (controller-per-operation, converter-per-type) with its enumerated members. */
export const VariantFamily = z.strictObject({
  familyId,
  rootCause: z.string().min(1).max(300),
  baselineId: baselineId.optional(),
  members: z
    .array(
      z.strictObject({ path: z.string().min(1), startLine: z.number().int().positive(), label: z.string().max(120) }),
    )
    .min(2)
    .max(40),
});
export type VariantFamily = z.infer<typeof VariantFamily>;

/** A pattern that looks like a bug but is intended or safe here; also handed to the validator. */
export const Carveout = z.strictObject({
  carveoutId,
  pattern: z.string().min(1).max(300),
  justification: z.string().min(1).max(500),
  evidence: z.array(SourceSpan).max(4).default([]),
  source: z.enum(['recon', 'operator']).default('recon'),
});
export type Carveout = z.infer<typeof Carveout>;

/** A question the source cannot settle (deployment, roles, tenancy, business policy). */
export const ResidualUnknown = z.strictObject({
  unknownId,
  question: z.string().min(1).max(400),
  whySourceCannotSettle: z.string().min(1).max(400),
  kind: z.enum(['architecture', 'deployment', 'role', 'tenant', 'business', 'policy']),
  /** Invariant or family ids whose verdict depends on the answer. */
  affects: z.array(z.string().max(40)).max(10).default([]),
});
export type ResidualUnknown = z.infer<typeof ResidualUnknown>;

/** An operator- or recon-stated fact about trust; `claimed` facts must be rechecked, never cited as proof. */
export const TrustClaim = z.strictObject({
  statement: z.string().min(1).max(400),
  provenance: z.string().min(1).max(200),
  confidence: z.enum(['claimed', 'verified']).default('claimed'),
});
export type TrustClaim = z.infer<typeof TrustClaim>;

export const Archetype = z.enum([
  'web_app',
  'http_api',
  'cms',
  'plugin',
  'library',
  'cli',
  'agent_llm',
  'mobile',
  'data_pipeline',
  'iac',
  'hybrid',
]);
export type Archetype = z.infer<typeof Archetype>;

export const GroundTruth = z.strictObject({
  archetype: Archetype,
  archetypeNote: z.string().max(400).default(''),
  trustClaims: z.array(TrustClaim).max(30).default([]),
  invariants: z.array(GroundTruthInvariant).max(40).default([]),
  baselines: z.array(BaselineReference).max(20).default([]),
  families: z.array(VariantFamily).max(12).default([]),
  carveouts: z.array(Carveout).max(20).default([]),
  residualUnknowns: z.array(ResidualUnknown).max(12).default([]),
  notes: z.array(z.string().max(300)).max(10).default([]),
});
export type GroundTruth = z.infer<typeof GroundTruth>;

/** Deliverable of the recon role: threat model and ground truth in one pass (`submit_recon`). */
export const ReconDeliverable = z.strictObject({
  threatModel: ThreatModel,
  groundTruth: GroundTruth,
});
export type ReconDeliverable = z.infer<typeof ReconDeliverable>;

/** One row of the audit's invariant checklist. */
export const InvariantResult = z.strictObject({
  invariantId,
  result: z.enum(['PASS', 'FAIL', 'UNKNOWN']),
  evidence: z.array(SourceSpan).max(4).default([]),
  note: z.string().max(400).default(''),
});
export type InvariantResult = z.infer<typeof InvariantResult>;

/** One row of the variant hunt log: every family member gets a verdict, not only the first. */
export const VariantHuntRow = z.strictObject({
  familyId,
  member: z.strictObject({ path: z.string().min(1), startLine: z.number().int().positive() }),
  verdict: z.enum(['SAFE', 'UNSURE', 'VULNERABLE']),
  evidence: SourceSpan.optional(),
  note: z.string().max(300).default(''),
});
export type VariantHuntRow = z.infer<typeof VariantHuntRow>;

/**
 * Claim contract (ADR-050): the exact, falsifiable statement a finding makes, separated from how
 * bad it is (severity) and how sure the author is (confidence).
 */
export const FindingClaim = z.strictObject({
  claim: z.string().min(1).max(300).describe('One falsifiable sentence: the security property that is broken'),
  preconditions: z.array(z.string().max(300)).max(8).default([]),
  capabilitiesGained: z.array(z.string().max(300)).max(8).default([]),
  proofObligations: z
    .array(z.string().max(300))
    .max(8)
    .default([])
    .describe('Links still unproven from source; empty only when the code settles every link'),
  threatModelClass: z
    .enum(['real_bug', 'broken_mechanism', 'by_design'])
    .default('real_bug')
    .describe(
      'real_bug: holds regardless of trust model; broken_mechanism: defeats a control the project ships; by_design: intended within the stated trust model (goes to notes, not findings)',
    ),
  baselineReference: baselineId.optional().describe('Baseline-correct reference this code deviates from'),
  invariantId: invariantId.optional(),
  familyId: familyId.optional(),
  /** Hook for blind second-opinion passes (not run yet). */
  sourcePass: z.string().max(40).optional(),
});
export type FindingClaim = z.infer<typeof FindingClaim>;

/** One finding reported by an investigator or the baseline auditor; the host assigns ids and fingerprints. */
export const AiFinding = z.strictObject({
  category: Category,
  cwe: z.array(CweId).min(1).max(4),
  title: z.string().min(1).max(160),
  summary: z.string().min(1).max(2000),
  confidence: Confidence,
  severity: Severity,
  attacker: z.string().max(200),
  invariantViolated: z.string().max(300).describe('The security property that does not hold'),
  ...FindingClaim.shape,
  locations: z
    .array(
      z.strictObject({
        path: z.string(),
        startLine: z.number().int().positive(),
        endLine: z.number().int().positive(),
        role: z.enum(['primary', 'source', 'sink', 'guard']),
      }),
    )
    .min(1)
    .max(8)
    .describe('Exactly one primary location: the line a developer must change'),
  evidence: z.array(z.string().max(400)).min(1).max(8),
  counterevidence: z.array(z.string().max(400)).max(6),
  remediation: z.string().min(1).max(800),
});
export type AiFinding = z.infer<typeof AiFinding>;

export const InvestigationResult = z.strictObject({
  findings: z.array(AiFinding).max(12),
  resolvedQuestions: z.array(z.strictObject({ question: z.string().max(300), answer: z.string().max(600) })).max(12),
  reviewedFiles: z.array(z.string()).max(60),
  deferred: z.array(z.string().max(300)).max(10).describe('Checks not finished within budget'),
  /** Closed-ended coverage (ADR-049): one row per invariant of the slice, one per family member. */
  invariantResults: z.array(InvariantResult).max(60).default([]),
  variantLog: z.array(VariantHuntRow).max(200).default([]),
});
export type InvestigationResult = z.infer<typeof InvestigationResult>;

/**
 * Reduced finding for small or prompted-tool models (ADR-054): one primary location and the claim
 * contract essentials. The host lifts it to `AiFinding` (defaults for attacker, obligations, roles)
 * and caps confidence at MEDIUM because proof obligations were not enumerated.
 */
export const AiFindingLite = z.strictObject({
  category: Category,
  cwe: z.array(CweId).min(1).max(2),
  title: z.string().min(1).max(160),
  summary: z.string().min(1).max(1200),
  severity: Severity,
  confidence: Confidence,
  claim: z.string().min(1).max(300).describe('One falsifiable sentence: the security property that is broken'),
  path: z.string(),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive().optional(),
  evidence: z.array(z.string().max(300)).min(1).max(4),
  remediation: z.string().min(1).max(500),
  preconditions: z.array(z.string().max(200)).max(4).default([]),
  capabilitiesGained: z.array(z.string().max(200)).max(4).default([]),
  invariantId: invariantId.optional(),
  familyId: familyId.optional(),
});
export type AiFindingLite = z.infer<typeof AiFindingLite>;

export const InvestigationResultLite = z.strictObject({
  findings: z.array(AiFindingLite).max(8),
  invariantResults: z.array(InvariantResult).max(40).default([]),
  variantLog: z.array(VariantHuntRow).max(80).default([]),
  deferred: z.array(z.string().max(200)).max(6).default([]),
  reviewedFiles: z.array(z.string()).max(40).default([]),
});
export type InvestigationResultLite = z.infer<typeof InvestigationResultLite>;

const findingRef = z.string().regex(/^F-\d{1,4}$/);

/** Findings from several shards that combine into a higher-impact path (ADR-055). */
export const AttackChain = z.strictObject({
  chainId: z.string().regex(/^CH-\d{1,3}$/),
  /** Host-assigned finding refs (`F-n`) in attack order. */
  members: z.array(findingRef).min(2).max(8),
  combinedSeverity: Severity,
  narrative: z.string().min(1).max(800),
  combinedPreconditions: z.array(z.string().max(200)).max(8).default([]),
});
export type AttackChain = z.infer<typeof AttackChain>;

/**
 * Reducer deliverable (ADR-055): verdicts about host-assigned refs, never finding bodies. A finding
 * can only be dropped (`keep: false`) with a rationale naming a carve-out or the duplicate it merges
 * into; the host converts anything else back to kept with low confidence (downgrade, don't delete).
 */
export const ReduceResult = z.strictObject({
  findings: z
    .array(
      z.strictObject({
        ref: findingRef,
        keep: z.boolean(),
        severity: Severity,
        confidence: Confidence,
        mergedInto: findingRef.optional(),
        rationale: z.string().max(400),
      }),
    )
    .max(300),
  chains: z.array(AttackChain).max(20).default([]),
  /** Refs most severe first. */
  ranking: z.array(findingRef).max(300).default([]),
  notes: z.array(z.string().max(300)).max(10).default([]),
});
export type ReduceResult = z.infer<typeof ReduceResult>;

/** Edits proposed by the remediation role; the host applies them to a workspace copy, never to the repository. */
export const PatchProposal = z.strictObject({
  summary: z.string().min(1).max(1500).describe('What the patch changes and why it closes the whole path'),
  edits: z
    .array(
      z.strictObject({
        path: z.string().min(1),
        startLine: z.number().int().positive(),
        endLine: z
          .number()
          .int()
          .positive()
          .describe('Inclusive; equal to startLine - 1 is not allowed, use replace of a single line instead'),
        /** New content for lines startLine..endLine (may contain more or fewer lines). */
        replacement: z.string().max(20_000),
        rationale: z.string().max(400),
      }),
    )
    .min(1)
    .max(12),
  behaviourPreserved: z
    .string()
    .min(1)
    .max(600)
    .describe('Legitimate behaviour that still works after the change, and how you checked'),
  tests: z.array(z.string().max(600)).max(6).describe('Tests that should be added or that cover the fix'),
  residualRisk: z.array(z.string().max(400)).max(6),
});
export type PatchProposal = z.infer<typeof PatchProposal>;

export const PatchStatus = z.enum(['verified', 'rescan_passed', 'no_change', 'blocked', 'failed']);
export type PatchStatus = z.infer<typeof PatchStatus>;

/** Outcome of `spinxsca fix` (ADR-026): only `verified` patches are offered for apply/PR. */
export const PatchResult = z.object({
  patchId: z.string(),
  findingId: z.string(),
  scanId: z.string(),
  status: PatchStatus,
  reason: z.string().optional(),
  proposal: PatchProposal.optional(),
  files: z.array(z.string()),
  /** Unified diff of the workspace against the snapshot. */
  diff: z.string().optional(),
  verification: z.object({
    rescan: z.enum(['RESOLVED', 'STILL_PRESENT', 'NOT_RUN', 'INCONCLUSIVE']),
    rescanScanId: z.string().optional(),
    newFindings: z.array(z.string()),
    tests: z.enum(['passed', 'failed', 'skipped', 'not_available']),
    testOutput: z.string().optional(),
  }),
  runId: z.string().optional(),
  createdAt: Timestamp,
});
export type PatchResult = z.infer<typeof PatchResult>;
