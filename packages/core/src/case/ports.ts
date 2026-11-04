import type {
  AgentStepRecord,
  ApprovalRecord,
  AuditEntry,
  AuditStage,
  CaseHandle,
  CaseLedger,
  CaseVerdict,
  CoverageCheck,
  Grant,
  JournalEntry,
  MemoryEntry,
  MemoryStatus,
  Objective,
  ReviewCase,
  ToolCallRecord,
  ToolCallStatus,
  WorkItem,
} from '@spinxsca/schemas';
import type { LedgerDelta } from './ledger';

export interface AuditAppend {
  caseId: string;
  stage: AuditStage;
  actor: string;
  toolCallId?: string;
  data: Record<string, unknown>;
}

export type JournalAppend = Omit<JournalEntry, 'seq' | 'prevHash' | 'hash' | 'at'> & { at?: string };

export interface ApprovalResolutionInput {
  status: 'APPROVED' | 'DENIED' | 'EXPIRED' | 'CANCELLED';
  resolvedBy: NonNullable<ApprovalRecord['resolvedBy']>;
  grantScope?: ApprovalRecord['grantScope'];
  reason?: string;
  resolvedAt: string;
}

/**
 * Case store (ADR-044). Journal and audit appends are hash chained under a per-case lock; approvals
 * are idempotent per (case, tool call) and the first responder wins; ledger charges are atomic.
 * Grants, approval resolution, memory status and objective waivers are human operations: the worker
 * RPC surface never exposes them.
 */
export interface CaseRepository {
  createCase(c: ReviewCase): Promise<void>;
  updateCase(caseId: string, patch: Partial<Omit<ReviewCase, 'caseId' | 'projectId'>>): Promise<ReviewCase>;
  getCase(caseId: string): Promise<ReviewCase | undefined>;
  listCases(filter: { projectId?: string; scanId?: string; limit?: number }): Promise<ReviewCase[]>;

  saveObjectives(objectives: readonly Objective[]): Promise<void>;
  listObjectives(caseId: string): Promise<Objective[]>;

  /** Insert or update; with `expectedUpdatedAt`, fails when the stored item changed meanwhile. */
  saveWorkItem(item: WorkItem, expectedUpdatedAt?: string): Promise<void>;
  getWorkItem(itemId: string): Promise<WorkItem | undefined>;
  listWorkItems(caseId: string): Promise<WorkItem[]>;

  appendJournal(entry: JournalAppend): Promise<JournalEntry>;
  listJournal(caseId: string, sinceSeq?: number): Promise<JournalEntry[]>;
  appendAudit(event: AuditAppend): Promise<AuditEntry>;
  listAudit(caseId: string, sinceSeq?: number): Promise<AuditEntry[]>;

  /** Idempotent per (agentRunId, index). */
  saveAgentStep(step: AgentStepRecord): Promise<void>;
  listAgentSteps(agentRunId: string): Promise<AgentStepRecord[]>;

  saveToolCall(call: ToolCallRecord): Promise<void>;
  getToolCall(caseId: string, toolCallId: string): Promise<ToolCallRecord | undefined>;
  listToolCalls(caseId: string, filter?: { agentRunId?: string; status?: ToolCallStatus }): Promise<ToolCallRecord[]>;

  /** Returns the existing approval when one is already recorded for the same (case, tool call). */
  createApproval(approval: ApprovalRecord): Promise<ApprovalRecord>;
  /** First responder wins: `won` is false when the approval was no longer pending. */
  resolveApproval(
    approvalId: string,
    input: ApprovalResolutionInput,
  ): Promise<{ won: boolean; approval: ApprovalRecord }>;
  getApproval(approvalId: string): Promise<ApprovalRecord | undefined>;
  findApproval(caseId: string, toolCallId: string): Promise<ApprovalRecord | undefined>;
  listApprovals(filter: {
    projectId?: string;
    caseId?: string;
    status?: ApprovalRecord['status'];
  }): Promise<ApprovalRecord[]>;

  saveGrant(grant: Grant): Promise<void>;
  revokeGrant(grantId: string, at: string): Promise<boolean>;
  listGrants(filter: { projectId: string; caseId?: string }): Promise<Grant[]>;

  getLedger(caseId: string): Promise<CaseLedger>;
  /** Atomic read-modify-write of the case ledger. */
  chargeLedger(caseId: string, delta: LedgerDelta): Promise<CaseLedger>;

  saveCheck(check: CoverageCheck): Promise<void>;
  listChecks(caseId: string): Promise<CoverageCheck[]>;

  saveVerdict(verdict: CaseVerdict): Promise<void>;
  listVerdicts(caseId: string): Promise<CaseVerdict[]>;

  saveHandles(handles: readonly CaseHandle[]): Promise<void>;
  listHandles(caseId: string): Promise<CaseHandle[]>;

  saveMemory(entry: MemoryEntry): Promise<void>;
  updateMemoryStatus(memoryId: string, status: MemoryStatus, reason: string, at: string): Promise<boolean>;
  listMemory(filter: { projectId: string; status?: MemoryStatus; kind?: MemoryEntry['kind'] }): Promise<MemoryEntry[]>;
}
