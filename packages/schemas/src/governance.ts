import { z } from 'zod';
import { Digest, Timestamp } from './common';

/**
 * Governance of autonomous review (ADR-041). Every tool call an agent proposes is classified by risk,
 * evaluated by a pure policy engine and, when the engine asks, resolved by an approver chain. The
 * model never chooses the risk class, the sandbox profile or who may approve.
 */
export const RiskClass = z.enum([
  /** Reads the snapshot, the code index, the knowledge base or the case store. */
  'READ',
  /** Writes to the case store only (journal, board, proposals). */
  'RECORD',
  /** Runs an analyzer in a network-less, read-only sandbox over a redacted copy. */
  'ANALYZE',
  /** Writes files inside a case workspace (a copy of the repository). */
  'WRITE_WORKSPACE',
  /** Executes repository code (tests, PoC harnesses) inside a sandbox. */
  'EXEC_REPO_CODE',
  /** Changes the real repository. Only a human-approved request may lead to it. */
  'WRITE_REPO',
  /** Acts on a system outside the host (pull requests, tickets). */
  'EXTERNAL',
  /** Changes what is scanned or how findings are judged (dispositions, baselines, excludes, rules). */
  'GOVERNANCE',
  /** Sends data to the network. Never allowed for agents. */
  'EGRESS',
]);
export type RiskClass = z.infer<typeof RiskClass>;

export const RISK_RANK: Record<RiskClass, number> = {
  READ: 0,
  RECORD: 1,
  ANALYZE: 2,
  WRITE_WORKSPACE: 3,
  EXEC_REPO_CODE: 4,
  WRITE_REPO: 5,
  EXTERNAL: 6,
  GOVERNANCE: 7,
  EGRESS: 8,
};

/**
 * Closed catalog of agent tools and their risk (ADR-041). A tool missing from the catalog is treated
 * as GOVERNANCE (fail closed); configuration can only raise a risk, never lower it.
 */
export const TOOL_RISK: Readonly<Record<string, RiskClass>> = {
  // Snapshot, index, knowledge base and case store reads.
  read_file: 'READ',
  search_code: 'READ',
  list_files: 'READ',
  list_findings: 'READ',
  list_endpoints: 'READ',
  auth_context: 'READ',
  get_symbol: 'READ',
  callers: 'READ',
  callees: 'READ',
  get_finding: 'READ',
  finding_evidence: 'READ',
  journal_read: 'READ',
  board_view: 'READ',
  kb_lookup: 'READ',
  deps_inventory: 'READ',
  deps_reachability: 'READ',
  resource_matrix: 'READ',
  data_access_sites: 'READ',
  // Phase 7 (ADR-056): paged access to large tool results and the repository digest.
  read_result: 'READ',
  repo_map: 'READ',
  load_skill: 'READ',
  explore: 'READ',
  // Case store writes.
  journal_record: 'RECORD',
  board_create_item: 'RECORD',
  board_update_item: 'RECORD',
  board_assign: 'RECORD',
  propose_disposition: 'RECORD',
  propose_memory: 'RECORD',
  submit_verdict: 'RECORD',
  // Sandboxed analysis over a redacted, read-only copy.
  run_scanner: 'ANALYZE',
  semgrep_rule: 'ANALYZE',
  shell_exec: 'ANALYZE',
  // Case workspaces and sandboxed execution of repository code.
  harness_write: 'WRITE_WORKSPACE',
  patch_propose: 'WRITE_WORKSPACE',
  validation_run: 'EXEC_REPO_CODE',
  verify_run: 'EXEC_REPO_CODE',
  // Requests that only a human can grant (L6).
  request_apply: 'WRITE_REPO',
  request_pr: 'EXTERNAL',
  request_tool: 'GOVERNANCE',
  request_memory_promotion: 'GOVERNANCE',
  request_rule_promotion: 'GOVERNANCE',
  request_objective_waiver: 'GOVERNANCE',
  request_standing_rule: 'GOVERNANCE',
  request_disposition: 'GOVERNANCE',
  /** Host-emitted review question (ADR-051); never offered to a model, answered by a human in the inbox. */
  request_context: 'GOVERNANCE',
  // Host-only actions; listed so that an agent naming them is denied by the floors.
  apply_patch: 'WRITE_REPO',
  set_disposition: 'GOVERNANCE',
  set_baseline: 'GOVERNANCE',
  disable_scanner: 'GOVERNANCE',
  add_exclude: 'GOVERNANCE',
  add_nosemgrep: 'GOVERNANCE',
  create_grant: 'GOVERNANCE',
  http_request: 'EGRESS',
};

/** Risk classes an operator may auto-allow (`ai.autonomy.auto_allow`). */
export const AUTO_ALLOWABLE_RISKS: ReadonlySet<RiskClass> = new Set([
  'READ',
  'RECORD',
  'ANALYZE',
  'WRITE_WORKSPACE',
  'EXEC_REPO_CODE',
]);

export const AutonomyMode = z.enum([
  /** Read and analyze only; nothing executes repository code or writes a workspace. */
  'observe',
  /** Asks a human (TTY, UI, inbox) for every action the policy does not allow outright. */
  'supervised',
  /** Like supervised, but a reviewer model may approve asks while a human is attended. */
  'autonomous',
]);
export type AutonomyMode = z.infer<typeof AutonomyMode>;

export const ReviewerMode = z.enum(['off', 'shadow', 'on']);
export type ReviewerMode = z.infer<typeof ReviewerMode>;

export const PolicyOutcome = z.enum(['allow', 'deny', 'ask']);
export type PolicyOutcome = z.infer<typeof PolicyOutcome>;

/** Precedence layers of the policy engine (docs/architecture/08 section 3). */
export const PolicyLayer = z.enum(['L0', 'L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7', 'L8', 'L9', 'L10', 'L11', 'L12']);
export type PolicyLayer = z.infer<typeof PolicyLayer>;

export const GrantScope = z.enum(['once', 'case', 'standing']);
export type GrantScope = z.infer<typeof GrantScope>;

export const ActionTarget = z.object({
  kind: z.enum([
    /** Repository-relative path in the snapshot. */
    'repo_path',
    /** `<workspaceId>/<relative path>` inside a case workspace. */
    'workspace_path',
    /** Absolute host path (only ever legitimate for host-owned tools). */
    'host_path',
    /** Case-local finding handle (CF-n). */
    'handle',
    'finding',
    'image',
    'network',
    'provider',
    /** A governance table (grants, approvals, dispositions, baselines, memory promotion). */
    'store',
    'url',
  ]),
  value: z.string(),
});
export type ActionTarget = z.infer<typeof ActionTarget>;

export const PolicyDecision = z.object({
  outcome: PolicyOutcome,
  layer: PolicyLayer,
  /** Stable rule identifier, e.g. "floor.network" (audit only, never shown to the agent). */
  rule: z.string(),
  risk: RiskClass,
  /** Diagnostic reason for operators and audit. */
  reason: z.string(),
  humanOnly: z.boolean(),
  offeredGrants: z.array(GrantScope),
  flags: z.array(z.string()),
});
export type PolicyDecision = z.infer<typeof PolicyDecision>;

/** A standing permission created by a human: `case` grants bind one case, `standing` rules a project. */
export const Grant = z.object({
  grantId: z.string(),
  projectId: z.string(),
  caseId: z.string().optional(),
  scope: z.enum(['case', 'standing']),
  tool: z.string(),
  /** Exact target for case grants; a glob for standing rules; "*" for any target. */
  target: z.string(),
  risk: RiskClass,
  reason: z.string().optional(),
  createdBy: z.string(),
  createdAt: Timestamp,
  expiresAt: Timestamp.optional(),
  revokedAt: Timestamp.optional(),
});
export type Grant = z.infer<typeof Grant>;

export const ApprovalStatus = z.enum(['PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'CANCELLED']);
export type ApprovalStatus = z.infer<typeof ApprovalStatus>;

export const ApproverKind = z.enum(['human', 'reviewer', 'policy', 'inbox']);
export type ApproverKind = z.infer<typeof ApproverKind>;

/** Durable approval request (inbox item). One per (case, tool call); the first responder wins. */
export const ApprovalRecord = z.object({
  approvalId: z.string(),
  projectId: z.string(),
  caseId: z.string(),
  toolCallId: z.string(),
  tool: z.string(),
  risk: RiskClass,
  humanOnly: z.boolean(),
  /** Plain-language title, e.g. "Run a proof-of-concept for CF-3 in the sandbox". */
  title: z.string(),
  summary: z.string(),
  /** Where the effect lands: "sandbox", "workspace" (a copy) or "repository". */
  effect: z.enum(['sandbox', 'workspace', 'repository', 'external', 'governance']),
  targets: z.array(ActionTarget),
  /** Redacted, truncated arguments. */
  argsPreview: z.string(),
  diff: z.string().optional(),
  offeredGrants: z.array(GrantScope),
  status: ApprovalStatus,
  requestedAt: Timestamp,
  resolvedAt: Timestamp.optional(),
  resolvedBy: z.object({ kind: ApproverKind, id: z.string() }).optional(),
  grantScope: GrantScope.optional(),
  reason: z.string().optional(),
});
export type ApprovalRecord = z.infer<typeof ApprovalRecord>;

export const AuditStage = z.enum([
  'case.started',
  'case.resumed',
  'case.stopped',
  'tool.proposed',
  'policy.decided',
  'approval.requested',
  'approval.resolved',
  'reviewer.verdict',
  'reviewer.shadow',
  'reviewer.breaker_tripped',
  'policy.breaker_tripped',
  'grant.created',
  'grant.refused',
  'grant.revoked',
  'tool.started',
  'tool.finished',
  'tool.failed',
  'tool.cancelled',
  'item.transition',
  'verdict.applied',
  'validation.oracle',
  'memory.proposed',
  'memory.status',
  'objective.status',
  // Operator run control (ADR-052): pause, resume or cancel requested.
  'case.control',
  // Phase 6 (ADR-050/051).
  'verdict.overridden',
  'context.asked',
  'context.answered',
]);
export type AuditStage = z.infer<typeof AuditStage>;

/** Genesis link of every hash chain (journal and audit). */
export const GENESIS_HASH = `sha256:${'0'.repeat(64)}`;

/** Tamper-evident audit record of one governance event (hash chained per case). */
export const AuditEntry = z.object({
  caseId: z.string(),
  seq: z.number().int().nonnegative(),
  stage: AuditStage,
  at: Timestamp,
  /** "host", "agent:<persona>/<runId>", "human:<principal>", "reviewer:<model>". */
  actor: z.string(),
  toolCallId: z.string().optional(),
  data: z.record(z.string(), z.unknown()),
  prevHash: Digest,
  hash: Digest,
});
export type AuditEntry = z.infer<typeof AuditEntry>;

/** Strict output of the reviewer model; anything else is treated as "unsure". */
export const ReviewerVerdict = z.strictObject({
  verdict: z.enum(['approve', 'deny', 'unsure']),
  reason: z.string().max(400),
});
export type ReviewerVerdict = z.infer<typeof ReviewerVerdict>;
