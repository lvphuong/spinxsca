import {
  answerContextQuestion,
  askContextQuestions,
  type CandidateDraft,
  contextQuestionId,
  declineContextQuestion,
} from '@spinxsca/core';
import { migrate, SqlCaseRepository, sqliteDriver } from '@spinxsca/storage';
import Database from 'better-sqlite3';
import { describe, expect, it } from 'vitest';

const now = new Date('2026-11-05T10:00:00Z');
const rc = { caseId: 'case_q1', projectId: 'prj_1' };

async function setup() {
  const db = new Database(':memory:');
  migrate(db);
  const cases = new SqlCaseRepository(sqliteDriver(db));
  await cases.createCase({
    caseId: rc.caseId,
    projectId: rc.projectId,
    scanId: 'scan_q1',
    snapshotId: 'snap_q1',
    goal: 'g',
    mode: 'supervised',
    attended: false,
    status: 'RUNNING',
    round: 0,
    policyDigest: `sha256:${'b'.repeat(64)}`,
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  });
  const draft: CandidateDraft = {
    scanner: 'ai-review',
    ruleId: 'ai-review.bola',
    ruleFamily: 'bola',
    category: 'BROKEN_OBJECT_LEVEL_AUTHORIZATION',
    cwe: ['CWE-639'],
    title: 'Any tenant reads any invoice',
    message: 'm',
    severityHint: 'HIGH',
    confidenceHint: 'MEDIUM',
    locations: [{ path: 'src/invoices.ts', startLine: 10, endLine: 12, role: 'primary' }],
    claim: {
      claim: 'A user of tenant A can read invoices of tenant B.',
      preconditions: [],
      capabilitiesGained: [],
      proofObligations: ['the gateway does not inject a tenant filter'],
      threatModelClass: 'real_bug',
      invariantId: 'INV-2',
    },
  };
  await cases.saveHandles([
    {
      caseId: rc.caseId,
      handle: 'CF-1',
      draftRef: `sha256:${'c'.repeat(64)}`,
      origin: 'agent',
      producer: { persona: 'logic', runId: 'run_1' },
      scanner: 'ai-review',
      ruleId: 'ai-review.bola',
      category: 'BROKEN_OBJECT_LEVEL_AUTHORIZATION',
      title: draft.title,
      severity: 'HIGH',
      path: 'src/invoices.ts',
      startLine: 10,
      vulnerabilityIds: [],
      draft,
    },
  ]);
  return cases;
}

describe('review questions (ADR-051)', () => {
  it('asks once per unknown as a human-only inbox item without parking the case', async () => {
    const cases = await setup();
    const unknowns = [
      {
        unknownId: 'RQ-1',
        question: 'Does the API gateway add a tenant filter to every query?',
        whySourceCannotSettle: 'the gateway configuration is not in this repository',
        kind: 'deployment' as const,
        affects: ['INV-2'],
      },
    ];
    const created = await askContextQuestions(cases, rc, unknowns, now);
    expect(created).toHaveLength(1);
    expect(created[0]).toMatchObject({
      tool: 'request_context',
      humanOnly: true,
      status: 'PENDING',
      effect: 'governance',
    });
    expect(created[0]?.approvalId).toBe(contextQuestionId(rc.caseId, 'RQ-1'));
    expect(await askContextQuestions(cases, rc, unknowns, now)).toEqual([]);
    expect((await cases.listApprovals({ caseId: rc.caseId, status: 'PENDING' })).map((a) => a.tool)).toEqual([
      'request_context',
    ]);
    expect((await cases.listAudit(rc.caseId)).map((a) => a.stage)).toContain('context.asked');
  });

  it('turns an answer into claimed memory and re-triages the findings that depend on it', async () => {
    const cases = await setup();
    const [q] = await askContextQuestions(
      cases,
      rc,
      [
        {
          unknownId: 'RQ-1',
          question: 'Gateway tenant filter?',
          whySourceCannotSettle: 'not in repo',
          kind: 'deployment',
          affects: ['INV-2'],
        },
      ],
      now,
    );
    const outcome = await answerContextQuestion(cases, q!.approvalId, {
      answer: 'No. The gateway only authenticates; tenancy is enforced in the service.',
      provenance: 'platform team reply 2026-11-05',
      by: 'alice',
      now,
    });
    expect(outcome.approval.status).toBe('APPROVED');
    expect(outcome.approval.reason).toContain('only authenticates');
    expect(outcome.memory).toMatchObject({ kind: 'ARCHITECTURE', status: 'active', key: 'context:RQ-1' });
    expect(outcome.memory?.text).toContain('confidence: claimed');
    expect(outcome.retriaged).toEqual(['CF-1']);
    const items = await cases.listWorkItems(rc.caseId);
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      kind: 'TRIAGE_FINDING',
      persona: 'validator',
      handles: ['CF-1'],
      mandatory: true,
    });
    expect(items[0]?.description).toContain('not source evidence');
    expect((await cases.listMemory({ projectId: rc.projectId, status: 'active' })).map((m) => m.key)).toEqual([
      'context:RQ-1',
    ]);
    expect((await cases.listAudit(rc.caseId)).map((a) => a.stage)).toContain('context.answered');
    await expect(
      answerContextQuestion(cases, q!.approvalId, { answer: 'again', provenance: 'p', by: 'bob', now }),
    ).rejects.toThrow('already approved');
  });

  it('keeps a declined question as a gap and refuses to answer non-question approvals', async () => {
    const cases = await setup();
    const [q] = await askContextQuestions(
      cases,
      rc,
      [
        {
          unknownId: 'RQ-9',
          question: 'Who holds the admin role?',
          whySourceCannotSettle: 'IAM',
          kind: 'role',
          affects: [],
        },
      ],
      now,
    );
    const declined = await declineContextQuestion(cases, q!.approvalId, {
      by: 'alice',
      reason: 'unknown to us too',
      now,
    });
    expect(declined.status).toBe('DENIED');
    const journal = await cases.listJournal(rc.caseId);
    expect(journal.some((e) => e.kind === 'GAP' && e.text.includes('RQ-9 remains open'))).toBe(true);
    await expect(
      answerContextQuestion(cases, 'apr_missing', { answer: 'a', provenance: 'p', by: 'x', now }),
    ).rejects.toThrow('not found');
    await expect(
      answerContextQuestion(cases, q!.approvalId, { answer: '', provenance: 'p', by: 'x', now }),
    ).rejects.toThrow();
  });
});
