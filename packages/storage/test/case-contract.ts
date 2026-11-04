import { type CaseRepository, verifyChain } from '@spinxsca/core';
import type { ApprovalRecord, ReviewCase, WorkItem } from '@spinxsca/schemas';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ConcurrentUpdateError } from '../src/index';

const now = '2026-11-01T00:00:00.000Z';
const digest = `sha256:${'e'.repeat(64)}`;

export function reviewCase(caseId: string, overrides: Partial<ReviewCase> = {}): ReviewCase {
  return {
    caseId,
    projectId: 'prj_1',
    scanId: 'scan_1',
    snapshotId: 'snap_1',
    goal: 'Review the API',
    mode: 'supervised',
    attended: true,
    status: 'RUNNING',
    round: 0,
    policyDigest: digest,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

function item(itemId: string, caseId: string): WorkItem {
  return {
    itemId,
    caseId,
    kind: 'TRIAGE_FINDING',
    title: 'Triage CF-1',
    description: '',
    status: 'todo',
    mandatory: true,
    persona: 'validator',
    handles: ['CF-1'],
    dependsOn: [],
    createdBy: 'host',
    round: 0,
    attempts: 0,
    createdAt: now,
    updatedAt: now,
  };
}

function approval(approvalId: string, caseId: string, toolCallId: string): ApprovalRecord {
  return {
    approvalId,
    projectId: 'prj_1',
    caseId,
    toolCallId,
    tool: 'validation_run',
    risk: 'EXEC_REPO_CODE',
    humanOnly: false,
    title: 'Run PoC',
    summary: 'sandbox',
    effect: 'sandbox',
    targets: [{ kind: 'handle', value: 'CF-1' }],
    argsPreview: '{}',
    offeredGrants: ['once', 'case'],
    status: 'PENDING',
    requestedAt: now,
  };
}

/** Behaviour every CaseRepository adapter must share (SQLite for the CLI, PostgreSQL for the service). */
export function caseRepositoryContract(
  name: string,
  open: () => Promise<{ repo: CaseRepository; close: () => Promise<void> | void }>,
): void {
  describe(`${name}: case repository contract`, () => {
    let repo: CaseRepository;
    let close: () => Promise<void> | void;
    beforeEach(async () => {
      ({ repo, close } = await open());
    });
    afterEach(async () => {
      await close();
    });

    it('stores, updates and lists cases', async () => {
      await repo.createCase(reviewCase('case_a'));
      await repo.createCase(reviewCase('case_b', { createdAt: '2026-11-02T00:00:00.000Z', scanId: 'scan_2' }));
      const updated = await repo.updateCase('case_a', { status: 'PARKED', round: 2 });
      expect(updated).toMatchObject({ status: 'PARKED', round: 2 });
      expect((await repo.getCase('case_a'))?.status).toBe('PARKED');
      expect((await repo.listCases({ projectId: 'prj_1' })).map((c) => c.caseId)).toEqual(['case_b', 'case_a']);
      expect((await repo.listCases({ scanId: 'scan_2' })).map((c) => c.caseId)).toEqual(['case_b']);
    });

    it('rejects concurrent work item updates with a stale version', async () => {
      const i = item('wi_1', 'case_a');
      await repo.saveWorkItem(i);
      await repo.saveWorkItem({ ...i, status: 'in_progress', updatedAt: '2026-11-01T00:00:01.000Z' }, now);
      await expect(repo.saveWorkItem({ ...i, status: 'blocked' }, now)).rejects.toBeInstanceOf(ConcurrentUpdateError);
      expect((await repo.getWorkItem('wi_1'))?.status).toBe('in_progress');
      expect(await repo.listWorkItems('case_a')).toHaveLength(1);
    });

    it('chains concurrent journal and audit appends without gaps', async () => {
      await Promise.all(
        Array.from({ length: 20 }, (_, i) =>
          repo.appendJournal({ caseId: 'case_a', kind: 'NOTE', author: 'host', handles: [], refs: [], text: `n${i}` }),
        ),
      );
      await Promise.all(
        Array.from({ length: 20 }, (_, i) =>
          repo.appendAudit({ caseId: 'case_a', stage: 'tool.finished', actor: 'host', data: { i } }),
        ),
      );
      await repo.appendAudit({ caseId: 'case_b', stage: 'case.started', actor: 'host', data: {} });
      const journal = await repo.listJournal('case_a');
      expect(journal.map((e) => e.seq)).toEqual([...Array(20).keys()]);
      expect(verifyChain(journal).ok).toBe(true);
      const audit = await repo.listAudit('case_a');
      expect(verifyChain(audit)).toMatchObject({ ok: true, length: 20 });
      expect((await repo.listAudit('case_a', 17)).map((e) => e.seq)).toEqual([18, 19]);
      expect(verifyChain(await repo.listAudit('case_b'))).toMatchObject({ ok: true, length: 1 });
    });

    it('creates one approval per tool call and lets the first responder win', async () => {
      const first = await repo.createApproval(approval('apr_1', 'case_a', 'call_1'));
      const again = await repo.createApproval(approval('apr_2', 'case_a', 'call_1'));
      expect(again.approvalId).toBe(first.approvalId);
      const [a, b] = await Promise.all([
        repo.resolveApproval('apr_1', {
          status: 'APPROVED',
          resolvedBy: { kind: 'human', id: 'alice' },
          grantScope: 'once',
          resolvedAt: now,
        }),
        repo.resolveApproval('apr_1', { status: 'DENIED', resolvedBy: { kind: 'human', id: 'bob' }, resolvedAt: now }),
      ]);
      expect([a.won, b.won].filter(Boolean)).toHaveLength(1);
      const stored = await repo.getApproval('apr_1');
      expect(stored?.status).toBe(a.won ? 'APPROVED' : 'DENIED');
      expect((await repo.findApproval('case_a', 'call_1'))?.approvalId).toBe('apr_1');
      expect(await repo.listApprovals({ projectId: 'prj_1', status: 'PENDING' })).toHaveLength(0);
      await repo.createApproval(approval('apr_3', 'case_a', 'call_2'));
      expect((await repo.listApprovals({ status: 'PENDING' })).map((x) => x.approvalId)).toEqual(['apr_3']);
    });

    it('charges the ledger atomically', async () => {
      await Promise.all(
        Array.from({ length: 25 }, () =>
          repo.chargeLedger('case_a', { costUsd: 0.1, sandboxRuns: 1, validationRunFor: 'CF-1', modelCalls: 1 }),
        ),
      );
      const ledger = await repo.getLedger('case_a');
      expect(ledger.sandboxRuns).toBe(25);
      expect(ledger.validationRuns['CF-1']).toBe(25);
      expect(ledger.costUsd).toBeCloseTo(2.5, 6);
      expect((await repo.getLedger('case_none')).sandboxRuns).toBe(0);
    });

    it('stores grants, revokes once and scopes case grants', async () => {
      const base = { projectId: 'prj_1', tool: 'harness_write', target: '*', risk: 'WRITE_WORKSPACE' as const };
      await repo.saveGrant({
        ...base,
        grantId: 'g1',
        scope: 'case',
        caseId: 'case_a',
        createdBy: 'human:a',
        createdAt: now,
      });
      await repo.saveGrant({ ...base, grantId: 'g2', scope: 'standing', createdBy: 'human:a', createdAt: now });
      await repo.saveGrant({
        ...base,
        grantId: 'g3',
        scope: 'case',
        caseId: 'case_b',
        createdBy: 'human:a',
        createdAt: now,
      });
      expect((await repo.listGrants({ projectId: 'prj_1', caseId: 'case_a' })).map((g) => g.grantId)).toEqual([
        'g1',
        'g2',
      ]);
      expect(await repo.revokeGrant('g1', now)).toBe(true);
      expect(await repo.revokeGrant('g1', now)).toBe(false);
      expect((await repo.listGrants({ projectId: 'prj_1' })).find((g) => g.grantId === 'g1')?.revokedAt).toBe(now);
    });

    it('keeps tool calls, steps, checks, verdicts, handles and memory', async () => {
      await repo.saveAgentStep({
        agentRunId: 'run_1',
        caseId: 'case_a',
        index: 0,
        kind: 'prompt',
        content: [{ type: 'text' }],
        at: now,
      });
      await repo.saveAgentStep({
        agentRunId: 'run_1',
        caseId: 'case_a',
        index: 0,
        kind: 'prompt',
        content: [{ type: 'text' }],
        at: now,
      });
      await repo.saveAgentStep({ agentRunId: 'run_1', caseId: 'case_a', index: 1, kind: 'turn', content: [], at: now });
      expect((await repo.listAgentSteps('run_1')).map((s) => s.index)).toEqual([0, 1]);

      const call = {
        caseId: 'case_a',
        toolCallId: 'tu_1',
        agentRunId: 'run_1',
        tool: 'read_file',
        risk: 'READ' as const,
        status: 'PROPOSED' as const,
        input: { path: 'a' },
        argsDigest: digest,
        createdAt: now,
        updatedAt: now,
      };
      await repo.saveToolCall(call);
      await repo.saveToolCall({ ...call, status: 'FINISHED', output: 'ok' });
      expect((await repo.getToolCall('case_a', 'tu_1'))?.status).toBe('FINISHED');
      expect(await repo.listToolCalls('case_a', { status: 'PROPOSED' })).toHaveLength(0);
      expect(await repo.listToolCalls('case_a', { agentRunId: 'run_1' })).toHaveLength(1);

      await repo.saveCheck({
        caseId: 'case_a',
        checkId: 'secrets-history',
        title: 'x',
        outcome: 'DEGRADED',
        reason: 'shallow',
        at: now,
      });
      await repo.saveCheck({ caseId: 'case_a', checkId: 'secrets-history', title: 'x', outcome: 'RAN', at: now });
      expect((await repo.listChecks('case_a')).map((c) => c.outcome)).toEqual(['RAN']);

      const v = {
        caseId: 'case_a',
        handle: 'CF-1',
        verdict: 'TRUE_POSITIVE' as const,
        classification: 'CONFIRMED' as const,
        confidence: 'HIGH' as const,
        verificationLevel: 'L2_CONTEXT' as const,
        rationale: 'r',
        counterevidence: [],
        evidence: [{ path: 'a.ts', startLine: 1, endLine: 2 }],
        at: now,
      };
      await repo.saveVerdict(v);
      await repo.saveVerdict({ ...v, verdict: 'FALSE_POSITIVE', at: '2026-11-01T00:00:05.000Z' });
      expect((await repo.listVerdicts('case_a')).map((x) => x.verdict)).toEqual(['TRUE_POSITIVE', 'FALSE_POSITIVE']);

      const h = {
        caseId: 'case_a',
        draftRef: 'sha256:1',
        origin: 'scanner' as const,
        scanner: 'semgrep',
        ruleId: 'r',
        category: 'SQL_INJECTION',
        title: 't',
        severity: 'HIGH' as const,
        path: 'a.ts',
        startLine: 1,
        vulnerabilityIds: [],
      };
      await repo.saveHandles([
        { ...h, handle: 'CF-10', draftRef: 'sha256:10' },
        { ...h, handle: 'CF-2', draftRef: 'sha256:2' },
      ]);
      expect((await repo.listHandles('case_a')).map((x) => x.handle)).toEqual(['CF-2', 'CF-10']);

      const m = {
        memoryId: 'mem_1',
        projectId: 'prj_1',
        kind: 'LESSON' as const,
        status: 'proposed' as const,
        key: 'k',
        text: 'Use parameterized queries in db/',
        createdBy: 'agent:lead/run_1',
        createdAt: now,
        updatedAt: now,
      };
      await repo.saveMemory(m);
      expect(await repo.updateMemoryStatus('mem_1', 'active', 'promoted by alice', now)).toBe(true);
      expect(await repo.updateMemoryStatus('mem_x', 'active', 'x', now)).toBe(false);
      expect((await repo.listMemory({ projectId: 'prj_1', status: 'active' })).map((x) => x.memoryId)).toEqual([
        'mem_1',
      ]);
      expect(await repo.listMemory({ projectId: 'prj_1', kind: 'ARCHITECTURE' })).toHaveLength(0);
    });
  });
}
