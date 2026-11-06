/** Shapes returned by the spinxsca server API (subset used by the app). */
export interface Project {
  projectId: string;
  name: string;
  source: { kind: 'git'; url: string } | { kind: 'local'; path: string };
  defaultBranch: string;
  ai?: { level: string; goal?: string; objectives?: string[] };
}

export interface ApprovalRecord {
  approvalId: string;
  projectId: string;
  caseId: string;
  toolCallId: string;
  tool: string;
  risk: string;
  humanOnly: boolean;
  title: string;
  summary: string;
  effect: 'sandbox' | 'workspace' | 'repository' | 'external' | 'governance';
  targets: Array<{ kind: string; value: string }>;
  argsPreview: string;
  diff?: string;
  offeredGrants: Array<'once' | 'case' | 'standing'>;
  status: string;
  requestedAt: string;
  project?: { projectId: string; name: string };
}

export interface ReviewCase {
  caseId: string;
  scanId: string;
  goal: string;
  mode: string;
  attended: boolean;
  status: string;
  stopReason?: string;
  round: number;
  createdAt: string;
}

export interface Objective {
  objectiveId: string;
  kind: string;
  title: string;
  status: string;
  reason?: string;
}

export interface CaseVerdict {
  handle: string;
  verdict: string;
  severity?: string;
  verificationLevel: string;
  rationale: string;
  applicability?: { status: string; reachability?: string; justification?: string };
  poc?: { outcome: string; oracle?: string };
}

export interface CaseHandle {
  handle: string;
  title: string;
  category: string;
  severity: string;
  path: string;
  startLine: number;
}

export interface CaseView {
  case: ReviewCase;
  objectives: Objective[];
  items: Array<{
    itemId: string;
    kind: string;
    status: string;
    persona: string;
    title: string;
    blockedReason?: string;
  }>;
  handles: CaseHandle[];
  verdicts: CaseVerdict[];
  checks: Array<{ checkId: string; outcome: string; reason?: string }>;
  ledger: { costUsd: number; modelCalls: number; sandboxRuns: number };
  approvals: ApprovalRecord[];
}

export interface AuditEvent {
  seq: number;
  stage: string;
  at: string;
  actor: string;
  data: Record<string, unknown>;
}

/** A queued unit of work on the local service (subset). Reviews scan first, then open a case. */
export interface JobEntry {
  jobId: string;
  kind: string;
  projectId?: string;
  payload: Record<string, unknown>;
  status: 'QUEUED' | 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'CANCELLED';
  attempts: number;
  maxAttempts: number;
  error?: string;
  createdAt: string;
  updatedAt: string;
}

export type AutonomyMode = 'observe' | 'supervised' | 'autonomous';

/** Options chosen before a review starts; the service only lets them narrow its configuration. */
export interface ReviewRunOptions {
  mode?: AutonomyMode;
  maxCostUsd?: number;
  maxRounds?: number;
  maxWallClockMin?: number;
  l3?: boolean;
  recon?: boolean;
  criticPasses?: number;
  scanners?: string[];
  acceptedRisks?: string[];
}

/** What the local service uses when a review sets no option, and the ceilings options obey. */
export interface ReviewDefaults {
  available: boolean;
  reason?: string;
  mode: AutonomyMode;
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

export type CaseControlAction = 'pause' | 'resume' | 'cancel';

/** Answer of a pause, resume or cancel request. `stoppedNow` is false while a remote run winds down. */
export interface CaseControlResult {
  case?: ReviewCase;
  job?: JobEntry;
  jobId?: string;
  stoppedNow?: boolean;
  remote?: boolean;
}
