import { z } from 'zod';
import { Confidence, Severity, Timestamp } from './common';
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
  role: z.enum(['explain', 'ask', 'planner', 'investigator', 'auditor', 'remediation']),
  scanId: z.string().optional(),
  findingId: z.string().optional(),
  /** Fingerprint of the occurrence that was explained, so a resumed scan can reuse the run. */
  subjectDigest: z.string().optional(),
  provider: z.string(),
  model: z.string(),
  modelsUsed: z.array(z.string()),
  promptBundleDigest: z.string(),
  status: z.enum(['COMPLETED', 'BUDGET_EXHAUSTED', 'REFUSED', 'FAILED', 'CANCELLED']),
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
      toolCalls: z.array(z.object({ name: z.string(), ok: z.boolean() })),
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
});
export type InvestigationResult = z.infer<typeof InvestigationResult>;

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
