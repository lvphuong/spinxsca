import {
  type ApprovalResolutionInput,
  type AuditAppend,
  applyLedgerDelta,
  type CaseRepository,
  emptyLedger,
  type JournalAppend,
  type LedgerDelta,
  link,
  SpinxscaError,
} from '@spinxsca/core';
import {
  AgentStepRecord,
  ApprovalRecord,
  AuditEntry,
  CaseHandle,
  CaseLedger,
  CaseVerdict,
  CoverageCheck,
  Grant,
  JournalEntry,
  MemoryEntry,
  type MemoryStatus,
  Objective,
  ReviewCase,
  ToolCallRecord,
  type ToolCallStatus,
  WorkItem,
} from '@spinxsca/schemas';
import { fromJson, type SqlDriver } from './driver';

type DataRow = { data: unknown };

export class ConcurrentUpdateError extends SpinxscaError {
  constructor(message: string) {
    super(message, 'CONFLICT');
    this.name = 'ConcurrentUpdateError';
  }
}

/** Case store over SQLite or PostgreSQL (ADR-044); one implementation, one contract test suite. */
export class SqlCaseRepository implements CaseRepository {
  constructor(
    private readonly db: SqlDriver,
    private readonly now: () => Date = () => new Date(),
  ) {}

  private async rows<T>(sql: string, params: readonly unknown[], parse: (v: unknown) => T, d = this.db): Promise<T[]> {
    return (await d.query<DataRow>(sql, params)).map((r) => parse(fromJson(r.data)));
  }

  private async upsert(
    table: string,
    keys: Record<string, unknown>,
    cols: Record<string, unknown>,
    d: SqlDriver = this.db,
  ): Promise<void> {
    const all = { ...keys, ...cols };
    const names = Object.keys(all);
    const updates = Object.keys(cols).map((c) => `${c} = excluded.${c}`);
    await d.run(
      `INSERT INTO {${table}} (${names.join(', ')}) VALUES (${names.map(() => '?').join(', ')})
       ON CONFLICT (${Object.keys(keys).join(', ')}) DO ${updates.length ? `UPDATE SET ${updates.join(', ')}` : 'NOTHING'}`,
      Object.values(all),
    );
  }

  // Cases

  async createCase(c: ReviewCase): Promise<void> {
    const v = ReviewCase.parse(c);
    await this.db.run(
      'INSERT INTO {review_cases} (case_id, project_id, scan_id, status, created_at, data) VALUES (?, ?, ?, ?, ?, ?)',
      [v.caseId, v.projectId, v.scanId, v.status, v.createdAt, v],
    );
  }

  async updateCase(caseId: string, patch: Partial<Omit<ReviewCase, 'caseId' | 'projectId'>>): Promise<ReviewCase> {
    return this.db.tx(async (d) => {
      const [current] = await this.rows(
        'SELECT data FROM {review_cases} WHERE case_id = ?',
        [caseId],
        ReviewCase.parse,
        d,
      );
      if (!current) throw new SpinxscaError(`case ${caseId} not found`, 'NOT_FOUND');
      const next = ReviewCase.parse({ ...current, ...patch, updatedAt: patch.updatedAt ?? this.now().toISOString() });
      await d.run('UPDATE {review_cases} SET status = ?, scan_id = ?, data = ? WHERE case_id = ?', [
        next.status,
        next.scanId,
        next,
        caseId,
      ]);
      return next;
    }, `case:${caseId}`);
  }

  async getCase(caseId: string): Promise<ReviewCase | undefined> {
    return (await this.rows('SELECT data FROM {review_cases} WHERE case_id = ?', [caseId], ReviewCase.parse))[0];
  }

  async listCases(filter: { projectId?: string; scanId?: string; limit?: number }): Promise<ReviewCase[]> {
    return this.rows(
      `SELECT data FROM {review_cases} WHERE (CAST(? AS TEXT) IS NULL OR project_id = ?) AND (CAST(? AS TEXT) IS NULL OR scan_id = ?)
       ORDER BY created_at DESC, case_id DESC LIMIT ?`,
      [
        filter.projectId ?? null,
        filter.projectId ?? null,
        filter.scanId ?? null,
        filter.scanId ?? null,
        filter.limit ?? 50,
      ],
      ReviewCase.parse,
    );
  }

  // Objectives and work items

  async saveObjectives(objectives: readonly Objective[]): Promise<void> {
    await this.db.tx(async (d) => {
      for (const o of objectives) {
        const v = Objective.parse(o);
        await this.upsert('case_objectives', { objective_id: v.objectiveId }, { case_id: v.caseId, data: v }, d);
      }
    });
  }

  async listObjectives(caseId: string): Promise<Objective[]> {
    return this.rows(
      'SELECT data FROM {case_objectives} WHERE case_id = ? ORDER BY objective_id',
      [caseId],
      Objective.parse,
    );
  }

  async saveWorkItem(item: WorkItem, expectedUpdatedAt?: string): Promise<void> {
    const v = WorkItem.parse(item);
    await this.db.tx(async (d) => {
      if (expectedUpdatedAt !== undefined) {
        const [row] = await d.query<{ updated_at: string }>('SELECT updated_at FROM {work_items} WHERE item_id = ?', [
          v.itemId,
        ]);
        if (row && row.updated_at !== expectedUpdatedAt) {
          throw new ConcurrentUpdateError(`work item ${v.itemId} changed concurrently`);
        }
      }
      await this.upsert(
        'work_items',
        { item_id: v.itemId },
        { case_id: v.caseId, status: v.status, updated_at: v.updatedAt, data: v },
        d,
      );
    }, `case:${v.caseId}`);
  }

  async getWorkItem(itemId: string): Promise<WorkItem | undefined> {
    return (await this.rows('SELECT data FROM {work_items} WHERE item_id = ?', [itemId], WorkItem.parse))[0];
  }

  async listWorkItems(caseId: string): Promise<WorkItem[]> {
    return this.rows('SELECT data FROM {work_items} WHERE case_id = ? ORDER BY item_id', [caseId], WorkItem.parse);
  }

  // Hash-chained journal and audit

  private async appendChained<T extends { seq: number; hash: string }>(
    table: 'case_journal' | 'case_audit',
    caseId: string,
    body: Record<string, unknown>,
    parse: (v: unknown) => T,
  ): Promise<T> {
    return this.db.tx(async (d) => {
      const [prev] = await this.rows(
        `SELECT data FROM {${table}} WHERE case_id = ? ORDER BY seq DESC LIMIT 1`,
        [caseId],
        parse,
        d,
      );
      const entry = parse(link(prev, body));
      await d.run(`INSERT INTO {${table}} (case_id, seq, hash, data) VALUES (?, ?, ?, ?)`, [
        caseId,
        entry.seq,
        entry.hash,
        entry,
      ]);
      return entry;
    }, `${table}:${caseId}`);
  }

  async appendJournal(entry: JournalAppend): Promise<JournalEntry> {
    const { at, ...rest } = entry;
    return this.appendChained(
      'case_journal',
      entry.caseId,
      { ...rest, at: at ?? this.now().toISOString() },
      JournalEntry.parse,
    );
  }

  async listJournal(caseId: string, sinceSeq = -1): Promise<JournalEntry[]> {
    return this.rows(
      'SELECT data FROM {case_journal} WHERE case_id = ? AND seq > ? ORDER BY seq',
      [caseId, sinceSeq],
      JournalEntry.parse,
    );
  }

  async appendAudit(event: AuditAppend): Promise<AuditEntry> {
    return this.appendChained(
      'case_audit',
      event.caseId,
      {
        caseId: event.caseId,
        stage: event.stage,
        at: this.now().toISOString(),
        actor: event.actor,
        ...(event.toolCallId ? { toolCallId: event.toolCallId } : {}),
        data: event.data,
      },
      AuditEntry.parse,
    );
  }

  async listAudit(caseId: string, sinceSeq = -1): Promise<AuditEntry[]> {
    return this.rows(
      'SELECT data FROM {case_audit} WHERE case_id = ? AND seq > ? ORDER BY seq',
      [caseId, sinceSeq],
      AuditEntry.parse,
    );
  }

  // Durable transcripts and tool calls

  async saveAgentStep(step: AgentStepRecord): Promise<void> {
    const v = AgentStepRecord.parse(step);
    await this.upsert('agent_steps', { agent_run_id: v.agentRunId, idx: v.index }, { case_id: v.caseId, data: v });
  }

  async listAgentSteps(agentRunId: string): Promise<AgentStepRecord[]> {
    return this.rows(
      'SELECT data FROM {agent_steps} WHERE agent_run_id = ? ORDER BY idx',
      [agentRunId],
      AgentStepRecord.parse,
    );
  }

  async saveToolCall(call: ToolCallRecord): Promise<void> {
    const v = ToolCallRecord.parse(call);
    await this.upsert(
      'tool_calls',
      { case_id: v.caseId, tool_call_id: v.toolCallId },
      { agent_run_id: v.agentRunId, status: v.status, created_at: v.createdAt, data: v },
    );
  }

  async getToolCall(caseId: string, toolCallId: string): Promise<ToolCallRecord | undefined> {
    return (
      await this.rows(
        'SELECT data FROM {tool_calls} WHERE case_id = ? AND tool_call_id = ?',
        [caseId, toolCallId],
        ToolCallRecord.parse,
      )
    )[0];
  }

  async listToolCalls(
    caseId: string,
    filter: { agentRunId?: string; status?: ToolCallStatus } = {},
  ): Promise<ToolCallRecord[]> {
    return this.rows(
      `SELECT data FROM {tool_calls} WHERE case_id = ? AND (CAST(? AS TEXT) IS NULL OR agent_run_id = ?) AND (CAST(? AS TEXT) IS NULL OR status = ?)
       ORDER BY created_at, tool_call_id`,
      [caseId, filter.agentRunId ?? null, filter.agentRunId ?? null, filter.status ?? null, filter.status ?? null],
      ToolCallRecord.parse,
    );
  }

  // Approvals (durable inbox) and grants

  async createApproval(approval: ApprovalRecord): Promise<ApprovalRecord> {
    const v = ApprovalRecord.parse(approval);
    return this.db.tx(async (d) => {
      const [existing] = await this.rows(
        'SELECT data FROM {approvals} WHERE case_id = ? AND tool_call_id = ?',
        [v.caseId, v.toolCallId],
        ApprovalRecord.parse,
        d,
      );
      if (existing) return existing;
      await d.run(
        'INSERT INTO {approvals} (approval_id, project_id, case_id, tool_call_id, status, requested_at, data) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [v.approvalId, v.projectId, v.caseId, v.toolCallId, v.status, v.requestedAt, v],
      );
      return v;
    }, `approval:${v.caseId}`);
  }

  async resolveApproval(
    approvalId: string,
    input: ApprovalResolutionInput,
  ): Promise<{ won: boolean; approval: ApprovalRecord }> {
    return this.db.tx(async (d) => {
      const [current] = await this.rows(
        'SELECT data FROM {approvals} WHERE approval_id = ?',
        [approvalId],
        ApprovalRecord.parse,
        d,
      );
      if (!current) throw new SpinxscaError(`approval ${approvalId} not found`, 'NOT_FOUND');
      if (current.status !== 'PENDING') return { won: false, approval: current };
      const next = ApprovalRecord.parse({
        ...current,
        status: input.status,
        resolvedAt: input.resolvedAt,
        resolvedBy: input.resolvedBy,
        ...(input.grantScope ? { grantScope: input.grantScope } : {}),
        ...(input.reason ? { reason: input.reason } : {}),
      });
      const changed = await d.run(
        "UPDATE {approvals} SET status = ?, data = ? WHERE approval_id = ? AND status = 'PENDING'",
        [next.status, next, approvalId],
      );
      return changed === 1 ? { won: true, approval: next } : { won: false, approval: current };
    }, `approval-id:${approvalId}`);
  }

  async getApproval(approvalId: string): Promise<ApprovalRecord | undefined> {
    return (
      await this.rows('SELECT data FROM {approvals} WHERE approval_id = ?', [approvalId], ApprovalRecord.parse)
    )[0];
  }

  async findApproval(caseId: string, toolCallId: string): Promise<ApprovalRecord | undefined> {
    return (
      await this.rows(
        'SELECT data FROM {approvals} WHERE case_id = ? AND tool_call_id = ?',
        [caseId, toolCallId],
        ApprovalRecord.parse,
      )
    )[0];
  }

  async listApprovals(filter: {
    projectId?: string;
    caseId?: string;
    status?: ApprovalRecord['status'];
  }): Promise<ApprovalRecord[]> {
    return this.rows(
      `SELECT data FROM {approvals} WHERE (CAST(? AS TEXT) IS NULL OR project_id = ?) AND (CAST(? AS TEXT) IS NULL OR case_id = ?) AND (CAST(? AS TEXT) IS NULL OR status = ?)
       ORDER BY requested_at, approval_id`,
      [
        filter.projectId ?? null,
        filter.projectId ?? null,
        filter.caseId ?? null,
        filter.caseId ?? null,
        filter.status ?? null,
        filter.status ?? null,
      ],
      ApprovalRecord.parse,
    );
  }

  async saveGrant(grant: Grant): Promise<void> {
    const v = Grant.parse(grant);
    await this.upsert(
      'grants',
      { grant_id: v.grantId },
      { project_id: v.projectId, case_id: v.caseId ?? null, created_at: v.createdAt, data: v },
    );
  }

  async revokeGrant(grantId: string, at: string): Promise<boolean> {
    return this.db.tx(async (d) => {
      const [g] = await this.rows('SELECT data FROM {grants} WHERE grant_id = ?', [grantId], Grant.parse, d);
      if (!g || g.revokedAt) return false;
      await d.run('UPDATE {grants} SET data = ? WHERE grant_id = ?', [{ ...g, revokedAt: at }, grantId]);
      return true;
    });
  }

  async listGrants(filter: { projectId: string; caseId?: string }): Promise<Grant[]> {
    return this.rows(
      'SELECT data FROM {grants} WHERE project_id = ? AND (case_id IS NULL OR CAST(? AS TEXT) IS NULL OR case_id = ?) ORDER BY created_at, grant_id',
      [filter.projectId, filter.caseId ?? null, filter.caseId ?? null],
      Grant.parse,
    );
  }

  // Ledger

  async getLedger(caseId: string): Promise<CaseLedger> {
    const [l] = await this.rows('SELECT data FROM {case_ledger} WHERE case_id = ?', [caseId], CaseLedger.parse);
    return l ?? emptyLedger(caseId, this.now());
  }

  async chargeLedger(caseId: string, delta: LedgerDelta): Promise<CaseLedger> {
    return this.db.tx(async (d) => {
      const [current] = await this.rows(
        'SELECT data FROM {case_ledger} WHERE case_id = ?',
        [caseId],
        CaseLedger.parse,
        d,
      );
      const next = applyLedgerDelta(current ?? emptyLedger(caseId, this.now()), delta, this.now());
      await this.upsert('case_ledger', { case_id: caseId }, { data: next }, d);
      return next;
    }, `ledger:${caseId}`);
  }

  // Coverage, verdicts, handles

  async saveCheck(check: CoverageCheck): Promise<void> {
    const v = CoverageCheck.parse(check);
    await this.upsert('case_checks', { case_id: v.caseId, check_id: v.checkId }, { data: v });
  }

  async listChecks(caseId: string): Promise<CoverageCheck[]> {
    return this.rows(
      'SELECT data FROM {case_checks} WHERE case_id = ? ORDER BY check_id',
      [caseId],
      CoverageCheck.parse,
    );
  }

  async saveVerdict(verdict: CaseVerdict): Promise<void> {
    const v = CaseVerdict.parse(verdict);
    await this.upsert('case_verdicts', { case_id: v.caseId, handle: v.handle, at: v.at }, { data: v });
  }

  async listVerdicts(caseId: string): Promise<CaseVerdict[]> {
    return this.rows(
      'SELECT data FROM {case_verdicts} WHERE case_id = ? ORDER BY at, handle',
      [caseId],
      CaseVerdict.parse,
    );
  }

  async saveHandles(handles: readonly CaseHandle[]): Promise<void> {
    if (handles.length === 0) return;
    await this.db.tx(async (d) => {
      for (const h of handles) {
        const v = CaseHandle.parse(h);
        await this.upsert(
          'case_handles',
          { case_id: v.caseId, handle: v.handle },
          { draft_ref: v.draftRef, data: v },
          d,
        );
      }
    });
  }

  async listHandles(caseId: string): Promise<CaseHandle[]> {
    const rows = await this.rows('SELECT data FROM {case_handles} WHERE case_id = ?', [caseId], CaseHandle.parse);
    return rows.sort((a, b) => Number(a.handle.slice(3)) - Number(b.handle.slice(3)));
  }

  // Memory

  async saveMemory(entry: MemoryEntry): Promise<void> {
    const v = MemoryEntry.parse(entry);
    await this.upsert(
      'memory_entries',
      { memory_id: v.memoryId },
      { project_id: v.projectId, kind: v.kind, status: v.status, mem_key: v.key, updated_at: v.updatedAt, data: v },
    );
  }

  async updateMemoryStatus(memoryId: string, status: MemoryStatus, reason: string, at: string): Promise<boolean> {
    return this.db.tx(async (d) => {
      const [m] = await this.rows(
        'SELECT data FROM {memory_entries} WHERE memory_id = ?',
        [memoryId],
        MemoryEntry.parse,
        d,
      );
      if (!m) return false;
      const next = { ...m, status, statusReason: reason, updatedAt: at };
      await d.run('UPDATE {memory_entries} SET status = ?, updated_at = ?, data = ? WHERE memory_id = ?', [
        status,
        at,
        next,
        memoryId,
      ]);
      return true;
    });
  }

  async listMemory(filter: {
    projectId: string;
    status?: MemoryStatus;
    kind?: MemoryEntry['kind'];
  }): Promise<MemoryEntry[]> {
    return this.rows(
      `SELECT data FROM {memory_entries} WHERE project_id = ? AND (CAST(? AS TEXT) IS NULL OR status = ?) AND (CAST(? AS TEXT) IS NULL OR kind = ?)
       ORDER BY updated_at, memory_id`,
      [filter.projectId, filter.status ?? null, filter.status ?? null, filter.kind ?? null, filter.kind ?? null],
      MemoryEntry.parse,
    );
  }
}
