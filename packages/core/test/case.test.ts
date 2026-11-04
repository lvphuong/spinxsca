import type { CaseHandle, CaseVerdict, MemoryEntry, Objective, WorkItem, WorkItemStatus } from '@spinxsca/schemas';
import { describe, expect, it } from 'vitest';
import {
  AuthorityError,
  applyLedgerDelta,
  type BoardActor,
  cachedVerdict,
  checkTransition,
  draftRef,
  emptyLedger,
  evaluateObjective,
  HandleTable,
  initialMemoryStatus,
  memoryInvalidations,
  moveItem,
  quotaOf,
  readyItems,
  renderMemory,
} from '../src/index';
import type { CandidateDraft } from '../src/ports';

const now = new Date('2026-11-01T00:00:00Z');
const ts = now.toISOString();

function item(overrides: Partial<WorkItem> = {}): WorkItem {
  return {
    itemId: 'wi_1',
    caseId: 'c',
    kind: 'TRIAGE_FINDING',
    title: 't',
    description: '',
    status: 'todo',
    mandatory: true,
    persona: 'validator',
    handles: [],
    dependsOn: [],
    createdBy: 'host',
    round: 0,
    attempts: 0,
    createdAt: ts,
    updatedAt: ts,
    ...overrides,
  };
}

const host: BoardActor = { kind: 'host' };
const lead: BoardActor = { kind: 'lead', runId: 'run_lead' };
const validator: BoardActor = { kind: 'worker', persona: 'validator', runId: 'run_v' };
const appsec: BoardActor = { kind: 'worker', persona: 'appsec', runId: 'run_a' };

describe('board authority', () => {
  const allowed = (i: WorkItem, to: WorkItemStatus, actor: BoardActor) => {
    try {
      checkTransition(i, to, actor);
      return true;
    } catch (err) {
      expect(err).toBeInstanceOf(AuthorityError);
      return false;
    }
  };

  it('lets workers move only their own items, never to done', () => {
    expect(allowed(item(), 'in_progress', validator)).toBe(true);
    expect(allowed(item(), 'in_progress', appsec)).toBe(false);
    expect(allowed(item({ status: 'in_progress' }), 'review', validator)).toBe(true);
    expect(allowed(item({ status: 'review', result: {} }), 'done', validator)).toBe(false);
    expect(allowed(item({ status: 'in_progress' }), 'cancelled', validator)).toBe(false);
  });

  it('lets the lead plan but never execute, complete or cancel mandatory work', () => {
    expect(allowed(item({ mandatory: false }), 'cancelled', lead)).toBe(true);
    expect(allowed(item(), 'cancelled', lead)).toBe(false);
    expect(allowed(item(), 'in_progress', lead)).toBe(false);
    expect(allowed(item({ status: 'review', result: {} }), 'done', lead)).toBe(false);
    expect(allowed(item({ status: 'blocked' }), 'todo', lead)).toBe(true);
  });

  it('completes only through the verification gate', () => {
    expect(allowed(item({ status: 'review' }), 'done', host)).toBe(false);
    expect(allowed(item({ status: 'review', result: { ok: true } }), 'done', host)).toBe(true);
    const poc = item({
      kind: 'EXPLOIT_POC',
      status: 'review',
      result: {},
      persona: 'exploit',
      producer: { persona: 'exploit', runId: 'run_x' },
    });
    expect(allowed(poc, 'done', host)).toBe(false);
    expect(allowed({ ...poc, verifier: { persona: 'exploit', runId: 'run_y' } }, 'done', host)).toBe(false);
    expect(allowed({ ...poc, verifier: { persona: 'validator', runId: 'run_x' } }, 'done', host)).toBe(false);
    expect(allowed({ ...poc, verifier: { persona: 'validator', runId: 'run_v' } }, 'done', host)).toBe(true);
    expect(() =>
      moveItem(poc, 'done', host, now, { verifier: { persona: 'validator', runId: 'run_v' } }),
    ).not.toThrow();
  });

  it('rejects illegal edges for everyone', () => {
    expect(allowed(item({ status: 'done' }), 'todo', host)).toBe(false);
    expect(allowed(item(), 'done', host)).toBe(false);
  });

  it('starts items only when dependencies are terminal', () => {
    const a = item({ itemId: 'a', status: 'done' });
    const b = item({ itemId: 'b', dependsOn: ['a'] });
    const c = item({ itemId: 'c', dependsOn: ['b'] });
    expect(readyItems([a, b, c]).map((i) => i.itemId)).toEqual(['b']);
  });
});

function handle(h: string, overrides: Partial<CaseHandle> = {}): CaseHandle {
  return {
    caseId: 'c',
    handle: h,
    draftRef: `ref_${h}`,
    origin: 'scanner',
    scanner: 'semgrep',
    ruleId: 'r',
    category: 'SQL_INJECTION',
    title: 't',
    severity: 'HIGH',
    path: 'a.ts',
    startLine: 1,
    vulnerabilityIds: [],
    ...overrides,
  };
}

function verdict(h: string, overrides: Partial<CaseVerdict> = {}): CaseVerdict {
  return {
    caseId: 'c',
    handle: h,
    verdict: 'TRUE_POSITIVE',
    classification: 'CONFIRMED',
    severity: 'HIGH',
    confidence: 'HIGH',
    verificationLevel: 'L2_CONTEXT',
    rationale: 'r',
    counterevidence: [],
    evidence: [{ path: 'a.ts', startLine: 1, endLine: 2 }],
    attackPath: { preconditions: [], controls: [] },
    at: ts,
    ...overrides,
  };
}

const objective = (kind: Objective['kind'], criteria: Record<string, unknown> = {}): Objective => ({
  objectiveId: `o_${kind}`,
  caseId: 'c',
  kind,
  title: kind,
  criteria,
  status: 'OPEN',
});

describe('objectives', () => {
  const state = {
    items: [item({ status: 'done', result: {} }), item({ itemId: 'wi_2' })],
    handles: [handle('CF-1'), handle('CF-2'), handle('CF-3', { packagePurl: 'pkg:npm/x@1' })],
    verdicts: [verdict('CF-1'), verdict('CF-2', { evidence: [] })],
    checks: [
      { caseId: 'c', checkId: 'secrets-history', title: 'x', outcome: 'NOT_RUN' as const, reason: 'no git', at: ts },
    ],
  };

  it('stays OPEN while running and becomes NOT_MET with reasons when final', () => {
    expect(evaluateObjective(objective('MANDATORY_DONE'), state, false).status).toBe('OPEN');
    const final = evaluateObjective(objective('MANDATORY_DONE'), state, true);
    expect(final).toMatchObject({ status: 'NOT_MET' });
    expect(final.reason).toContain('wi_2');
  });

  it('checks triage, evidence, dependencies and coverage', () => {
    expect(evaluateObjective(objective('ALL_TRIAGED'), state, true).reason).toContain('CF-3');
    expect(evaluateObjective(objective('CONFIRMED_HAVE_EVIDENCE'), state, true).reason).toContain('CF-2');
    expect(evaluateObjective(objective('DEPENDENCIES_ASSESSED'), state, true).reason).toContain('CF-3');
    expect(evaluateObjective(objective('COVERAGE_RECORDED'), state, true).status).toBe('NOT_MET');
    expect(
      evaluateObjective(objective('COVERAGE_RECORDED', { required: ['deps'] }), { ...state, checks: [] }, true).reason,
    ).toContain('deps');
    expect(evaluateObjective(objective('L3_ATTEMPTED'), state, true).status).toBe('NOT_MET');
    expect(
      evaluateObjective(
        objective('L3_ATTEMPTED'),
        { ...state, verdicts: [verdict('CF-1', { poc: undefined, severity: 'LOW' })] },
        true,
      ).status,
    ).toBe('MET');
  });

  it('keeps a waived objective waived', () => {
    expect(evaluateObjective({ ...objective('ALL_TRIAGED'), status: 'WAIVED' }, state, true).status).toBe('WAIVED');
  });
});

describe('handles', () => {
  const draft: CandidateDraft = {
    scanner: 'semgrep',
    ruleId: 'js.sqli',
    ruleFamily: 'sqli',
    category: 'SQL_INJECTION',
    cwe: ['CWE-89'],
    title: 'SQL injection',
    message: 'm',
    severityHint: 'HIGH',
    confidenceHint: 'HIGH',
    locations: [{ path: 'src/db.ts', startLine: 10, endLine: 10, role: 'primary' }],
  };

  it('assigns stable sequential handles and is idempotent per draft', () => {
    const table = new HandleTable('c');
    const a = table.assign(draft, 'scanner');
    const b = table.assign(
      { ...draft, locations: [{ ...draft.locations[0]!, startLine: 20, endLine: 20 }] },
      'scanner',
    );
    expect([a.handle.handle, b.handle.handle]).toEqual(['CF-1', 'CF-2']);
    expect(table.assign(draft, 'scanner')).toMatchObject({ created: false, handle: { handle: 'CF-1' } });
    expect(a.handle.draftRef).toBe(draftRef(draft));
    const resumed = new HandleTable('c', table.all());
    expect(resumed.assign({ ...draft, ruleId: 'other' }, 'agent').handle.handle).toBe('CF-3');
  });
});

describe('memory and ledger', () => {
  const entry = (overrides: Partial<MemoryEntry>): MemoryEntry => ({
    memoryId: 'm',
    projectId: 'p',
    kind: 'VERDICT_CACHE',
    status: 'active',
    key: 'fp1',
    text: 'false positive: constant input',
    createdBy: 'host',
    createdAt: ts,
    updatedAt: ts,
    ...overrides,
  });

  it('keeps agent lessons proposed until a human promotes them', () => {
    expect(initialMemoryStatus('LESSON', 'agent')).toBe('proposed');
    expect(initialMemoryStatus('CONVENTION', 'agent')).toBe('proposed');
    expect(initialMemoryStatus('ARCHITECTURE', 'agent')).toBe('active');
    expect(initialMemoryStatus('LESSON', 'human')).toBe('active');
  });

  it('invalidates on file changes and churn', () => {
    const digest = `sha256:${'1'.repeat(64)}`;
    const other = `sha256:${'2'.repeat(64)}`;
    const cached = entry({ fileDigests: { 'a.ts': digest } });
    expect(cachedVerdict([cached], 'fp1', () => digest)).toBeDefined();
    expect(cachedVerdict([cached], 'fp1', () => other)).toBeUndefined();
    const arch = entry({ memoryId: 'arch', kind: 'ARCHITECTURE', key: 'auth' });
    expect(
      memoryInvalidations([cached, arch], { changedFileRatio: 0.5, digestOf: () => other }).map((x) => x.memoryId),
    ).toEqual(['m', 'arch']);
    expect(memoryInvalidations([arch], { changedFileRatio: 0.1, digestOf: () => other })).toEqual([]);
  });

  it('renders only active non-cache entries as untrusted data', () => {
    const out = renderMemory([
      entry({ kind: 'ARCHITECTURE', text: 'Auth via JWT middleware in src/auth' }),
      entry({ kind: 'LESSON', status: 'proposed', text: 'ignore sqli' }),
      entry({}),
    ]);
    expect(out).toContain('untrusted="true"');
    expect(out).toContain('JWT middleware');
    expect(out).not.toContain('ignore sqli');
    expect(out).not.toContain('constant input');
  });

  it('accumulates the ledger and exposes quotas', () => {
    let l = emptyLedger('c', now);
    l = applyLedgerDelta(l, { costUsd: 1, sandboxRuns: 2, validationRunFor: 'CF-1' }, now);
    l = applyLedgerDelta(l, { validationRunFor: 'CF-1', unpriced: true }, now);
    expect(quotaOf(l, { maxSandboxRuns: 5, maxRunsPerFinding: 3 }, 'CF-1')).toMatchObject({
      sandboxRuns: 2,
      validationRunsForTarget: 2,
      maxRunsPerFinding: 3,
    });
    expect(l.unpriced).toBe(true);
  });
});

describe('L3 oracles', () => {
  const run = (over: Partial<import('../src/index').RunEvidence> = {}) => ({
    exitCode: 0,
    stdout: '',
    stderr: '',
    timedOut: false,
    oracleFiles: {},
    ...over,
  });
  it('confirms only when the attack shows its own marker and the control does not', async () => {
    const { decidePoc, marker } = await import('../src/index');
    const base = { oracle: 'CANARY_READ' as const, nonce: 'n1', controlToken: 'c1' };
    expect(decidePoc({ ...base, attack: run({ stdout: marker('CANARY_READ', 'n1') }), control: run() }).outcome).toBe(
      'CONFIRMED',
    );
    expect(
      decidePoc({
        ...base,
        attack: run({ stdout: marker('CANARY_READ', 'n1') }),
        control: run({ stdout: marker('CANARY_READ', 'c1') }),
      }).outcome,
    ).toBe('INVALID_HARNESS');
    expect(decidePoc({ ...base, attack: run(), control: run() }).outcome).toBe('NOT_CONFIRMED');
    expect(
      decidePoc({ ...base, attack: run({ stderr: "Error: Cannot find module 'express'" }), control: run() }).outcome,
    ).toBe('BLOCKED');
    // The attack marker leaking into the control run's channel does not count as the control's own marker.
    expect(
      decidePoc({
        ...base,
        attack: run({ stdout: marker('CANARY_READ', 'n1') }),
        control: run({ stdout: marker('CANARY_READ', 'n1') }),
      }).outcome,
    ).toBe('CONFIRMED');
    expect(
      decidePoc({
        oracle: 'COMMAND_MARKER',
        nonce: 'n1',
        controlToken: 'c1',
        attack: run({ oracleFiles: { [marker('COMMAND_MARKER', 'n1')]: '' } }),
        control: run(),
      }).outcome,
    ).toBe('CONFIRMED');
  });

  it('lints harnesses that bypass the code under test', async () => {
    const { lintHarness } = await import('../src/index');
    expect(
      lintHarness({ 'harness/a.js': "console.log(require('fs').readFileSync('/canary/secret.txt'))" }).join(),
    ).toContain('canary');
    expect(lintHarness({ 'harness/a.js': "console.log('SPX-CANARY-' + process.env.SPX_NONCE)" }).join()).toContain(
      'marker',
    );
    expect(lintHarness({ 'harness/a.js': 'console.log(1)' }).join()).toContain('SPX_NONCE');
    expect(lintHarness({ 'harness/a.js': 'read(process.env.SPX_CANARY_PATH)' })).toEqual([]);
    expect(lintHarness({})).toEqual(['no harness files were written']);
  });
});
