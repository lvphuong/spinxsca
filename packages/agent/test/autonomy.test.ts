import { join } from 'node:path';
import {
  type CandidateDraft,
  ControlRequestedError,
  createSecretScrubber,
  type DependencyPort,
  type ReviewSubject,
  type SourceTree,
  verifyChain,
} from '@spinxsca/core';
import type { AgentRunRecord, ScanRun } from '@spinxsca/schemas';
import { migrate, SqlCaseRepository, sqliteDriver } from '@spinxsca/storage';
import Database from 'better-sqlite3';
import { describe, expect, it } from 'vitest';
import {
  AgentAutonomousReviewer,
  type AutonomyConfig,
  caseReport,
  decideStop,
  duplicateGroups,
  ScriptedReviewProvider,
  seedBoard,
} from '../src/index';

const ROOT = join(import.meta.dirname, '../../..');
const files: Record<string, string> = {
  'src/db.js': [
    "const db = require('./conn');",
    'module.exports.find = (req) =>',
    '  db.query("SELECT * FROM users WHERE id = " + req.query.id);',
    '',
  ].join('\n'),
  'src/index.js': "const _ = require('lodash');\nmodule.exports = (a, b) => _.defaultsDeep({}, a, b);\n",
  'package-lock.json': `${'{\n'.repeat(1)}${'  "x": 1,\n'.repeat(20)}}\n`,
  Dockerfile: 'FROM node:22\nCOPY . .\n',
};
const source: SourceTree = {
  root: '/repo',
  listFiles: async () => [],
  readText: async (p) => files[p],
  gitInfo: async () => undefined,
};

const drafts: CandidateDraft[] = [
  {
    scanner: 'semgrep',
    ruleId: 'spinxsca-core.js.sqli.concat',
    ruleFamily: 'sqli',
    category: 'SQL_INJECTION',
    cwe: ['CWE-89'],
    title: 'SQL query built from request data',
    message: 'm',
    severityHint: 'HIGH',
    confidenceHint: 'HIGH',
    locations: [{ path: 'src/db.js', startLine: 3, endLine: 3, role: 'primary' }],
  },
  {
    scanner: 'osv-scanner',
    ruleId: 'GHSA-35jh-r3h4-6jhm',
    ruleFamily: 'vulnerable-dependency',
    category: 'VULNERABLE_DEPENDENCY',
    cwe: ['CWE-1395'],
    title: 'lodash 4.17.15: Command Injection in lodash',
    message: 'm',
    severityHint: 'HIGH',
    confidenceHint: 'HIGH',
    locations: [{ path: 'package-lock.json', startLine: 14, endLine: 18, role: 'primary' }],
    package: {
      purl: 'pkg:npm/lodash@4.17.15',
      ecosystem: 'npm',
      name: 'lodash',
      version: '4.17.15',
      manifestPath: 'package-lock.json',
    },
    vulnerabilityIds: ['GHSA-35jh-r3h4-6jhm'],
  },
];

const dependencies: DependencyPort = {
  inventory: async () => [
    {
      ecosystem: 'npm',
      name: 'lodash',
      version: '4.17.15',
      manifestPath: 'package-lock.json',
      direct: true,
      scope: 'runtime',
      purl: 'pkg:npm/lodash@4.17.15',
    },
  ],
  reachability: async (input) => ({
    level: input.symbols?.includes('template') ? 'IMPORTED_ONLY' : 'CALLED',
    confidence: 'MEDIUM',
    symbolSource: input.symbols?.length ? 'model' : 'none',
    importSites: [{ path: 'src/index.js', line: 1, specifier: 'lodash' }],
    callSites: input.symbols?.includes('template') ? [] : [{ path: 'src/index.js', line: 2, callee: '_.defaultsDeep' }],
    entrypoints: [],
    detail: 'fake',
  }),
};

const config: AutonomyConfig = {
  mode: 'supervised',
  reviewer: 'on',
  attended: false,
  autoAllow: [],
  denyTools: [],
  extraProtected: [],
  riskOverrides: {},
  maxRounds: 6,
  maxCostUsd: 10,
  maxSandboxRuns: 20,
  maxSandboxCpuSec: 600,
  maxWallClockMin: 10,
  maxParallel: 3,
  allowUnpriced: false,
  l3: false,
  maxRunsPerFinding: 3,
  remediation: false,
  dataPolicyExclude: [],
  protectedRoots: [],
};

function setup(overrides: Partial<AutonomyConfig> = {}) {
  const db = new Database(':memory:');
  migrate(db);
  const cases = new SqlCaseRepository(sqliteDriver(db));
  const provider = new ScriptedReviewProvider();
  const runs: AgentRunRecord[] = [];
  const reviewer = new AgentAutonomousReviewer({
    provider: () => provider,
    promptsDir: join(ROOT, 'prompts'),
    playbooksDir: join(ROOT, 'playbooks'),
    config: { ...config, ...overrides },
    goal: 'Review this service for exploitable vulnerabilities.',
  });
  const scan = { scanId: 'scan_01test', projectId: 'prj_1', snapshotId: 'snap_1' } as ScanRun;
  const subject: ReviewSubject = {
    scan,
    snapshotPaths: Object.keys(files),
    scannerDrafts: drafts,
    redactions: [],
    scrubber: createSecretScrubber(),
    ports: {
      cases,
      dependencies,
      history: { scan: async () => ({ outcome: 'RAN', secrets: [] }) },
      images: { toolbox: `sha256:${'a'.repeat(64)}`, scanners: {} },
      workDir: '/tmp/spx-case',
    },
  };
  const run = () => reviewer.review(subject, source, { maxCostUsd: 5, onRun: async (r) => void runs.push(r) });
  return { cases, provider, runs, run, reviewer };
}

describe('autonomous review case (scripted)', () => {
  it('seeds mandatory work, triages every finding and converges with met objectives', async () => {
    const { cases, run, runs } = setup();
    const outcome = await run();
    expect(outcome.status).toBe('CONVERGED');
    const byHandle = new Map(outcome.verdicts.map((v) => [v.verdict.handle, v.verdict]));
    expect(byHandle.get('CF-1')).toMatchObject({
      verdict: 'TRUE_POSITIVE',
      severity: 'HIGH',
      validator: { persona: 'validator' },
    });
    expect(byHandle.get('CF-2')).toMatchObject({
      verdict: 'FALSE_POSITIVE',
      applicability: {
        status: 'NOT_AFFECTED',
        reachability: 'IMPORTED_ONLY',
        justification: 'vulnerable_code_not_in_execute_path',
      },
    });
    const objectives = await cases.listObjectives(outcome.caseId);
    expect(objectives.map((o) => `${o.kind}:${o.status}`)).toEqual(
      expect.arrayContaining([
        'MANDATORY_DONE:MET',
        'ALL_TRIAGED:MET',
        'CONFIRMED_HAVE_EVIDENCE:MET',
        'DEPENDENCIES_ASSESSED:MET',
        'COVERAGE_RECORDED:MET',
      ]),
    );
    const items = await cases.listWorkItems(outcome.caseId);
    expect(items.every((i) => i.status === 'done')).toBe(true);
    expect(items.map((i) => i.kind).sort()).toEqual(
      ['BASELINE_AUDIT', 'DEPENDENCY_APPLICABILITY', 'IAC_REVIEW', 'REPORT', 'SECRETS_SWEEP', 'TRIAGE_FINDING'].sort(),
    );
    const audit = await cases.listAudit(outcome.caseId);
    expect(verifyChain(audit).ok).toBe(true);
    expect(audit.map((a) => a.stage)).toEqual(
      expect.arrayContaining(['case.started', 'policy.decided', 'tool.finished', 'verdict.applied', 'case.stopped']),
    );
    expect(verifyChain(await cases.listJournal(outcome.caseId)).ok).toBe(true);
    expect(new Set(runs.map((r) => r.personaId))).toEqual(
      new Set(['lead', 'validator', 'dependency', 'secrets', 'iac', 'appsec']),
    );
    expect(runs.every((r) => r.caseId === outcome.caseId)).toBe(true);
    const ledger = await cases.getLedger(outcome.caseId);
    expect(ledger.modelCalls).toBeGreaterThan(0);
    const report = caseReport({
      rc: (await cases.getCase(outcome.caseId))!,
      objectives,
      items,
      handles: await cases.listHandles(outcome.caseId),
      verdicts: await cases.listVerdicts(outcome.caseId),
      checks: await cases.listChecks(outcome.caseId),
      ledger,
      pendingApprovals: 0,
    });
    expect(report).toContain('| CF-2 |');
    expect(report).toContain('NOT_AFFECTED/IMPORTED_ONLY');
  });

  it('resumes a finished case without calling the model again', async () => {
    const { run, provider } = setup();
    const first = await run();
    const calls = provider.requests.length;
    const second = await run();
    expect(provider.requests.length).toBe(calls);
    expect(second.status).toBe('CONVERGED');
    expect(second.verdicts.map((v) => v.verdict.verdict).sort()).toEqual(
      first.verdicts.map((v) => v.verdict.verdict).sort(),
    );
  });

  it('stops on the cost budget and reports unfinished mandatory work as NOT_RUN', async () => {
    const { run, cases } = setup({ maxCostUsd: 0 });
    const outcome = await run();
    expect(outcome.status).toBe('BUDGET_EXHAUSTED');
    const checks = await cases.listChecks(outcome.caseId);
    expect(checks.filter((c) => c.checkId.startsWith('item:')).every((c) => c.outcome === 'NOT_RUN' && c.reason)).toBe(
      true,
    );
    const objectives = await cases.listObjectives(outcome.caseId);
    expect(objectives.find((o) => o.kind === 'MANDATORY_DONE')?.status).toBe('NOT_MET');
  });
});

describe('conductor and convergence', () => {
  it('seeds threat packets per endpoint file and custom objectives', () => {
    const { items, objectives } = seedBoard({
      caseId: 'c',
      now: new Date('2026-11-01T00:00:00Z'),
      handles: [],
      endpoints: [
        { id: 'e1', method: 'GET', route: '/a', path: 'src/a.js', line: 1 },
        { id: 'e2', method: 'POST', route: '/a', path: 'src/a.js', line: 5 },
        { id: 'e3', method: 'GET', route: '/b', path: 'src/b.js', line: 1 },
      ],
      iacFiles: [],
      l3: true,
      objectives: ['Can a tenant read another tenant invoice?'],
    });
    expect(items.filter((i) => i.kind === 'THREAT_PACKET').map((i) => i.description.split('\n').length)).toEqual([
      2, 1,
    ]);
    expect(items.find((i) => i.kind === 'HYPOTHESIS')).toMatchObject({ mandatory: true, persona: 'appsec' });
    expect(items.find((i) => i.kind === 'REPORT')?.dependsOn.length).toBe(items.length - 1);
    expect(objectives.map((o) => o.kind)).toEqual(expect.arrayContaining(['CUSTOM', 'L3_ATTEMPTED']));
  });

  it('decides stop reasons', () => {
    const base = { round: 1, maxRounds: 6, roundsWithoutProgress: 0, parkedItems: new Set<string>(), cancelled: false };
    const item = (status: 'todo' | 'done' | 'blocked', itemId = 'a') =>
      ({ itemId, status, persona: 'validator' }) as never;
    expect(decideStop({ ...base, items: [item('done')] })?.stop).toBe('CONVERGED');
    expect(decideStop({ ...base, items: [item('todo')], parkedItems: new Set(['a']) })?.stop).toBe('PARKED');
    expect(decideStop({ ...base, items: [item('todo')], roundsWithoutProgress: 2 })?.stop).toBe('STAGNATED');
    expect(decideStop({ ...base, items: [item('todo')], round: 6 })?.stop).toBe('BUDGET_EXHAUSTED');
    expect(decideStop({ ...base, items: [item('todo')], cancelled: true })?.stop).toBe('CANCELLED');
    expect(decideStop({ ...base, items: [item('todo')] })).toBeUndefined();
  });

  it('groups nearby duplicates as hints only', () => {
    const h = (handle: string, line: number) => ({ handle, category: 'XSS', path: 'a.js', startLine: line }) as never;
    expect(duplicateGroups([h('CF-1', 10), h('CF-2', 12), h('CF-3', 40)])).toEqual([['CF-1', 'CF-2']]);
  });
});

describe('L3 proof of concept flow (scripted, fake sandbox)', () => {
  it('seeds a PoC for a confirmed HIGH traversal, reviews the harness independently and records L3', async () => {
    const runs: Array<{ handle: string; workspaceId: string }> = [];
    const harness: Record<string, string> = {};
    const lastRuns = new Map<string, import('@spinxsca/core').ValidationRunResult>();
    const validation: import('@spinxsca/core').ValidationPort = {
      open: async (handle) => ({ workspaceId: `ws-${handle.toLowerCase()}`, interpreters: ['node'] }),
      workspaces: () => ['ws-cf-1'],
      writeHarness: async (_ws, path, content) => {
        harness[`harness/${path}`] = content;
      },
      harnessFiles: async () => harness,
      run: async ({ workspaceId, handle, command, oracle }) => {
        runs.push({ handle, workspaceId });
        const r = {
          workspaceId,
          handle,
          oracle,
          command: [...command],
          outcome: 'CONFIRMED' as const,
          attackTriggered: true,
          controlTriggered: false,
          detail: 'the attack run produced its marker and the control run did not',
          harnessDigest: `sha256:${'b'.repeat(64)}` as const,
          attackLog: 'SPX-CANARY-<NONCE>',
          controlLog: 'index',
          lintProblems: [],
          at: new Date().toISOString(),
        };
        lastRuns.set(`${workspaceId}|${handle}`, r);
        return r;
      },
      lastRun: async (ws, handle) => lastRuns.get(`${ws}|${handle}`),
    };
    const db = new Database(':memory:');
    migrate(db);
    const cases = new SqlCaseRepository(sqliteDriver(db));
    const reviewer = new AgentAutonomousReviewer({
      provider: () => new ScriptedReviewProvider(),
      promptsDir: join(ROOT, 'prompts'),
      playbooksDir: join(ROOT, 'playbooks'),
      config: { ...config, l3: true },
      goal: 'Prove what you can.',
    });
    const traversal: CandidateDraft = {
      ...drafts[0]!,
      ruleId: 'spinxsca-core.js.path-traversal',
      category: 'PATH_TRAVERSAL',
      cwe: ['CWE-22'],
      title: 'File path built from request data',
    };
    const outcome = await reviewer.review(
      {
        scan: { scanId: 'scan_01poc', projectId: 'prj_1', snapshotId: 'snap_1' } as ScanRun,
        snapshotPaths: Object.keys(files),
        scannerDrafts: [traversal],
        redactions: [],
        scrubber: createSecretScrubber(),
        ports: {
          cases,
          validation,
          images: {
            toolbox: `sha256:${'a'.repeat(64)}`,
            scanners: {},
            interpreters: { node: `node@sha256:${'c'.repeat(64)}` },
          },
          workDir: '/tmp/spx-case',
        },
      },
      source,
      { maxCostUsd: 5 },
    );
    expect(outcome.status).toBe('CONVERGED');
    expect(runs).toEqual([{ handle: 'CF-1', workspaceId: 'ws-cf-1' }]);
    const verdict = outcome.verdicts.find((v) => v.verdict.handle === 'CF-1')?.verdict;
    expect(verdict).toMatchObject({
      verdict: 'TRUE_POSITIVE',
      verificationLevel: 'L3_CONTROLLED',
      classification: 'CONFIRMED',
      poc: { outcome: 'CONFIRMED', oracle: 'CANARY_READ' },
    });
    const items = await cases.listWorkItems(outcome.caseId);
    const poc = items.find((i) => i.kind === 'EXPLOIT_POC');
    const review = items.find((i) => i.kind === 'REVIEW_POC');
    expect(poc).toMatchObject({ status: 'done', persona: 'exploit', verifier: { persona: 'validator' } });
    expect(poc?.producer?.runId).not.toBe(poc?.verifier?.runId);
    expect(review?.status).toBe('done');
    const objectives = await cases.listObjectives(outcome.caseId);
    expect(objectives.find((o) => o.kind === 'L3_ATTEMPTED')?.status).toBe('MET');
    const audit = await cases.listAudit(outcome.caseId);
    // validation_run was allowed by the operator's L3 setting without asking anyone.
    const decided = audit.filter((a) => a.stage === 'policy.decided' && a.data.tool === 'validation_run');
    expect(decided.map((a) => `${a.data.outcome} ${a.data.layer} ${a.data.rule}`)).toEqual([
      'allow L11 config.validation_l3',
    ]);
    expect(audit.some((a) => a.stage === 'validation.oracle')).toBe(true);
  });
});

describe('case remediation (scripted)', () => {
  async function setupCase() {
    const s = setup();
    const outcome = await s.run();
    return { ...s, caseId: outcome.caseId };
  }
  const patch = (patchId: string, status: 'verified' | 'failed') =>
    ({
      patchId,
      findingId: 'SPX-000001',
      scanId: 'scan_01test',
      status,
      reason: status === 'verified' ? 'finding resolved in re-scan and project tests pass' : 'still present',
      files: ['src/db.js'],
      diff: '--- a/src/db.js\n+++ b/src/db.js\n-  db.query("SELECT ..." + id)\n+  db.query("SELECT ... WHERE id = ?", [id])',
      proposal: { summary: 'parameterize', edits: [], behaviourPreserved: 'same rows', tests: [], residualRisk: [] },
      verification: { rescan: status === 'verified' ? 'RESOLVED' : 'STILL_PRESENT', newFindings: [], tests: 'passed' },
      runId: `run_fix_${patchId}`,
      createdAt: '2026-11-01T00:00:00Z',
    }) as import('@spinxsca/schemas').PatchResult;

  it('applies a verified, independently reviewed fix only after a human approves', async () => {
    const { cases, caseId } = await setupCase();
    const applied: string[] = [];
    const db = cases;
    const humanAnswers: string[] = [];
    const reviewer = new AgentAutonomousReviewer({
      provider: () => new ScriptedReviewProvider(),
      promptsDir: join(ROOT, 'prompts'),
      playbooksDir: join(ROOT, 'playbooks'),
      config: { ...config, attended: true, mode: 'autonomous' },
      goal: 'fix',
      human: async (request) => {
        humanAnswers.push(`${request.tool}:${request.humanOnly}:${request.effect}`);
        return { approved: true, grant: 'standing' };
      },
    });
    const results = await reviewer.remediate({
      cases: db,
      caseId,
      source,
      snapshotPaths: Object.keys(files),
      redactions: [],
      scrubber: createSecretScrubber(),
      targets: [{ findingId: 'SPX-000001', title: 'SQL injection', severity: 'HIGH', location: 'src/db.js:3' }],
      fix: async () => ({ result: patch('patch_1', 'verified'), attempts: [] }),
      apply: async (id) => {
        applied.push(id);
        return ['src/db.js'];
      },
    });
    expect(results).toEqual([expect.objectContaining({ status: 'applied', patchId: 'patch_1' })]);
    expect(applied).toEqual(['patch_1']);
    // Asked once, as a human-only repository change; the standing grant asked for was not honoured.
    expect(humanAnswers).toEqual(['request_apply:true:repository']);
    const [approval] = await db.listApprovals({ caseId });
    expect(approval).toMatchObject({ status: 'APPROVED', humanOnly: true });
    expect(approval?.grantScope).toBeUndefined();
    const fixItem = (await db.listWorkItems(caseId)).find((i) => i.kind === 'FIX');
    expect(fixItem).toMatchObject({
      status: 'done',
      producer: { persona: 'fixer' },
      verifier: { persona: 'verifier' },
    });
    expect(await db.listGrants({ projectId: 'prj_1' })).toEqual([]);
  });

  it('parks the apply request when nobody is attending and never applies', async () => {
    const { cases, caseId, reviewer } = await setupCase();
    const applied: string[] = [];
    const results = await reviewer.remediate({
      cases,
      caseId,
      source,
      snapshotPaths: Object.keys(files),
      redactions: [],
      scrubber: createSecretScrubber(),
      targets: [{ findingId: 'SPX-000001', title: 'SQL injection', severity: 'HIGH', location: 'src/db.js:3' }],
      fix: async () => ({ result: patch('patch_2', 'verified'), attempts: [] }),
      apply: async (id) => {
        applied.push(id);
        return [];
      },
    });
    expect(results[0]).toMatchObject({ status: 'awaiting_approval' });
    expect(applied).toEqual([]);
    expect((await cases.listApprovals({ caseId, status: 'PENDING' }))[0]).toMatchObject({
      tool: 'request_apply',
      humanOnly: true,
      effect: 'repository',
    });
  });

  it('does not send an unverified patch to review or to a human', async () => {
    const { cases, caseId, reviewer } = await setupCase();
    const results = await reviewer.remediate({
      cases,
      caseId,
      source,
      snapshotPaths: Object.keys(files),
      redactions: [],
      scrubber: createSecretScrubber(),
      targets: [{ findingId: 'SPX-000001', title: 'SQL injection', severity: 'HIGH', location: 'src/db.js:3' }],
      fix: async () => ({ result: patch('patch_3', 'failed'), attempts: [] }),
      apply: async () => {
        throw new Error('must not apply');
      },
    });
    expect(results[0]).toMatchObject({ status: 'unverified' });
    expect(await cases.listApprovals({ caseId })).toEqual([]);
  });
});

describe('recon-first review case (ADR-049, ADR-050, scripted)', () => {
  const logicFiles: Record<string, string> = {
    'orders/orders.controller.ts': [
      "import { Controller, Get, Param, Req, UseGuards } from '@nestjs/common';",
      '@Controller("orders")',
      '@UseGuards(JwtAuthGuard)',
      'export class OrdersController {',
      '  constructor(private readonly orders: OrdersService) {}',
      "  @Get(':id')",
      "  async findOne(@Param('id') id: string) {",
      '    return this.orders.findById(id);',
      '  }',
      '  @Get()',
      '  async mine(@Req() req: AuthenticatedRequest) {',
      '    return this.orders.findByOwner(req.user.id);',
      '  }',
      '}',
    ].join('\n'),
    'orders/orders.service.ts': [
      'export class OrdersService {',
      '  constructor(private readonly prisma: PrismaService) {}',
      '  findById(id: string) {',
      '    return this.prisma.order.findUnique({ where: { id } });',
      '  }',
      '  findByOwner(ownerId: string) {',
      '    return this.prisma.order.findMany({ where: { ownerId } });',
      '  }',
      '}',
    ].join('\n'),
  };
  const C = 'orders/orders.controller.ts::OrdersController';
  const S = 'orders/orders.service.ts::OrdersService';
  const sym = (key: string, path: string, name: string, start: number, end: number, owner: string) => ({
    key,
    path,
    name,
    qualifiedName: name,
    kind: 'method' as const,
    startLine: start,
    endLine: end,
    exported: true,
    owner,
  });
  const symbols: Record<string, ReturnType<typeof sym>> = {
    [`${C}.findOne`]: sym(`${C}.findOne`, 'orders/orders.controller.ts', 'findOne', 7, 9, C),
    [`${C}.mine`]: sym(`${C}.mine`, 'orders/orders.controller.ts', 'mine', 11, 13, C),
    [`${S}.findById`]: sym(`${S}.findById`, 'orders/orders.service.ts', 'findById', 3, 5, S),
    [`${S}.findByOwner`]: sym(`${S}.findByOwner`, 'orders/orders.service.ts', 'findByOwner', 6, 8, S),
  };
  const endpoints = [
    {
      id: 'GET /orders/:id',
      path: 'orders/orders.controller.ts',
      line: 6,
      method: 'GET',
      route: '/orders/:id',
      framework: 'nestjs',
      handlers: [`${C}.findOne`],
      controls: [],
    },
    {
      id: 'GET /orders',
      path: 'orders/orders.controller.ts',
      line: 10,
      method: 'GET',
      route: '/orders',
      framework: 'nestjs',
      handlers: [`${C}.mine`],
      controls: [],
    },
  ];
  const guard = {
    ref: 'JwtAuthGuard',
    name: 'JwtAuthGuard',
    kind: 'AUTHENTICATION',
    source: 'decorator',
    path: 'orders/orders.controller.ts',
    line: 3,
  };
  const graph: import('@spinxsca/core').CodeGraphView = {
    symbolCount: 4,
    getSymbol: (key) => symbols[key],
    symbolAt: () => undefined,
    search: () => [],
    callers: () => [],
    callees: (key) => {
      const to = key === `${C}.findOne` ? `${S}.findById` : key === `${C}.mine` ? `${S}.findByOwner` : undefined;
      return to ? [{ from: key, to, path: 'orders/orders.controller.ts', line: 8, confidence: 'HIGH' }] : [];
    },
    endpoints: () => endpoints,
    authContext: (id) => {
      const e = endpoints.find((x) => x.id === id);
      if (!e) return undefined;
      const handler = symbols[e.handlers[0] ?? ''];
      return {
        endpoint: e,
        handlers: handler ? [handler] : [],
        controls: [guard],
        hasAuthentication: true,
        hasAuthorization: false,
      };
    },
    callSitesIn: (path) =>
      path === 'orders/orders.service.ts'
        ? [
            { line: 4, callerKey: `${S}.findById`, callee: 'this.prisma.order.findUnique', name: 'findUnique' },
            { line: 7, callerKey: `${S}.findByOwner`, callee: 'this.prisma.order.findMany', name: 'findMany' },
          ]
        : [],
    filePaths: () => Object.keys(logicFiles),
  };
  const logicSource: SourceTree = {
    root: '/repo',
    listFiles: async () => [],
    readText: async (p) => logicFiles[p],
    gitInfo: async () => undefined,
  };

  function setupLogic(scannerDrafts: CandidateDraft[] = []) {
    const db = new Database(':memory:');
    migrate(db);
    const cases = new SqlCaseRepository(sqliteDriver(db));
    const provider = new ScriptedReviewProvider();
    const reviewer = new AgentAutonomousReviewer({
      provider: () => provider,
      promptsDir: join(ROOT, 'prompts'),
      playbooksDir: join(ROOT, 'playbooks'),
      config: {
        ...config,
        recon: { enabled: true, criticPasses: 1, maxLogicItems: 8, census: true },
        context: {
          accepted_risks: ['Admins may list every order.'],
          roles: [],
          trust_claims: [],
          business_invariants: [],
        },
      },
      goal: 'Find authorization and logic flaws.',
    });
    const scan = { scanId: 'scan_02logic', projectId: 'prj_1', snapshotId: 'snap_2' } as ScanRun;
    const subject: ReviewSubject = {
      scan,
      snapshotPaths: Object.keys(logicFiles),
      graph,
      scannerDrafts,
      redactions: [],
      scrubber: createSecretScrubber(),
      ports: {
        cases,
        history: { scan: async () => ({ outcome: 'RAN', secrets: [] }) },
        images: { toolbox: `sha256:${'a'.repeat(64)}`, scanners: {} },
        workDir: '/tmp/spx-case',
      },
    };
    return { cases, provider, run: () => reviewer.review(subject, logicSource, { maxCostUsd: 5 }) };
  }

  it('seeds recon and logic audits, validates the agent finding with a claim contract and converges', async () => {
    const { cases, provider, run } = setupLogic();
    const outcome = await run();
    expect(outcome.status).toBe('CONVERGED');
    const items = await cases.listWorkItems(outcome.caseId);
    const kinds = items.map((i) => i.kind);
    expect(kinds).toEqual(
      expect.arrayContaining(['RECON', 'LOGIC_AUDIT', 'COMPLETENESS_CRITIC', 'THREAT_PACKET', 'TRIAGE_FINDING']),
    );
    const recon = items.find((i) => i.kind === 'RECON');
    expect(recon?.status).toBe('done');
    const reconResult = recon?.result as { groundTruth: import('@spinxsca/schemas').GroundTruth } | undefined;
    expect(reconResult?.groundTruth.invariants).toHaveLength(1);
    expect(items.find((i) => i.kind === 'THREAT_PACKET')?.dependsOn).toEqual([`${outcome.caseId}:recon`]);
    const logic = items.find((i) => i.kind === 'LOGIC_AUDIT');
    expect(logic?.persona).toBe('logic');
    expect(logic?.status).toBe('done');
    const critics = items.filter((i) => i.kind === 'COMPLETENESS_CRITIC');
    expect(critics.length).toBeGreaterThanOrEqual(1);
    expect(critics.every((c) => c.status === 'done' && c.itemId.endsWith('-critic-1'))).toBe(true);
    // The agent finding became a handle with its claim contract and an independent validator confirmed it.
    const handles = await cases.listHandles(outcome.caseId);
    const agent = handles.find((h) => h.origin === 'agent');
    expect(agent?.category).toBe('BROKEN_OBJECT_LEVEL_AUTHORIZATION');
    expect((agent?.draft as CandidateDraft | undefined)?.claim?.claim).toContain('authenticated user');
    const verdict = outcome.verdicts.find((v) => v.verdict.handle === agent?.handle)?.verdict;
    expect(verdict?.verdict).toBe('TRUE_POSITIVE');
    expect(outcome.drafts.map((d) => d.scanner)).toEqual(['ai-review']);
    const prompts = provider.requests.map((r) => JSON.stringify(r.messages[0]));
    const triagePrompt = prompts.find((p) => p.includes('Reported by: logic'));
    expect(triagePrompt).toContain('<claim_contract');
    expect(triagePrompt).toContain('CO-900');
    const logicPrompt = prompts.find((p) => p.includes('Work item: LOGIC_AUDIT'));
    expect(logicPrompt).toContain('<ground_truth');
    expect(logicPrompt).toContain('INV-1');
    const criticPrompt = prompts.find((p) => p.includes('Work item: COMPLETENESS_CRITIC'));
    expect(criticPrompt).toContain('Already reported');
    const validatorSystem = provider.requests.find((r) =>
      JSON.stringify(r.messages[0]).includes('Reported by: logic'),
    )?.system;
    expect(validatorSystem).toContain('Admins may list every order.');
    expect(validatorSystem).toContain("Downgrade, don't delete");
    const objectives = await cases.listObjectives(outcome.caseId);
    expect(objectives.map((o) => `${o.kind}:${o.status}`)).toEqual(
      expect.arrayContaining(['INVARIANTS_CHECKED:MET', 'FAMILIES_SWEPT:MET', 'MANDATORY_DONE:MET']),
    );
    const report = caseReport({
      rc: (await cases.getCase(outcome.caseId))!,
      objectives,
      items,
      handles,
      verdicts: await cases.listVerdicts(outcome.caseId),
      checks: await cases.listChecks(outcome.caseId),
      ledger: await cases.getLedger(outcome.caseId),
      pendingApprovals: 0,
      ...(reconResult ? { groundTruth: reconResult.groundTruth } : {}),
    });
    expect(report).toContain('## Ground truth');
    expect(report).toContain('1 invariants');
  });

  it('rejects a refutation without a cited contradiction and keeps the finding as BLOCKED', async () => {
    const { cases, provider, run } = setupLogic([
      {
        ...(drafts[0] as CandidateDraft),
        title: 'SQL query built from request data scripted:expect-false-positive',
        locations: [{ path: 'orders/orders.service.ts', startLine: 4, endLine: 4, role: 'primary' }],
      },
    ]);
    const outcome = await run();
    const verdict = outcome.verdicts.find((v) => v.verdict.handle === 'CF-1')?.verdict;
    expect(verdict?.verdict).toBe('BLOCKED');
    const triage = provider.requests.filter(
      (r) => r.tools.some((t) => t.name === 'submit_triage') && JSON.stringify(r.messages[0]).includes('CF-1'),
    );
    const rejection = triage
      .flatMap((r) => r.messages.flatMap((m) => m.content))
      .find((b) => b.type === 'tool_result' && b.isError);
    expect(rejection && 'content' in rejection ? rejection.content : '').toContain('cited path:line');
    const journal = await cases.listJournal(outcome.caseId);
    expect(journal.some((e) => e.kind === 'VERDICT' && e.text.startsWith('BLOCKED'))).toBe(true);
  });
});

describe('operator run control (ADR-052)', () => {
  function pausable(pauseOnCall: number, action: 'pause' | 'cancel' = 'pause') {
    const db = new Database(':memory:');
    migrate(db);
    const cases = new SqlCaseRepository(sqliteDriver(db));
    const inner = new ScriptedReviewProvider();
    const controller = new AbortController();
    let calls = 0;
    // Stops the run from inside a model call, as the worker does when an operator clicks Pause.
    const provider = {
      id: inner.id,
      model: inner.model,
      capabilities: () => inner.capabilities(),
      complete: async (request: Parameters<ScriptedReviewProvider['complete']>[0]) => {
        calls++;
        if (calls === pauseOnCall) controller.abort(new ControlRequestedError(action, 'alice'));
        return inner.complete(request);
      },
    };
    const reviewer = new AgentAutonomousReviewer({
      provider: () => provider,
      promptsDir: join(ROOT, 'prompts'),
      playbooksDir: join(ROOT, 'playbooks'),
      config,
      goal: 'Review this service.',
      runOptions: { maxCostUsd: 3, recon: false },
    });
    const scan = { scanId: 'scan_01pause', projectId: 'prj_1', snapshotId: 'snap_1' } as ScanRun;
    const subject: ReviewSubject = {
      scan,
      snapshotPaths: Object.keys(files),
      scannerDrafts: drafts,
      redactions: [],
      scrubber: createSecretScrubber(),
      ports: {
        cases,
        dependencies,
        history: { scan: async () => ({ outcome: 'RAN', secrets: [] }) },
        images: { toolbox: `sha256:${'a'.repeat(64)}`, scanners: {} },
        workDir: '/tmp/spx-case',
      },
    };
    return {
      cases,
      calls: () => calls,
      run: (signal?: AbortSignal) => reviewer.review(subject, source, { maxCostUsd: 5, ...(signal ? { signal } : {}) }),
      signal: controller.signal,
    };
  }

  it('pauses mid-run without losing work, then resumes to convergence', async () => {
    const { cases, run, signal } = pausable(3);
    const paused = await run(signal);
    expect(paused.status).toBe('PAUSED');
    const rc = await cases.getCase(paused.caseId);
    expect(rc).toMatchObject({ status: 'PAUSED', stopReason: 'paused by alice' });
    expect(rc?.completedAt).toBeUndefined();
    const items = await cases.listWorkItems(paused.caseId);
    // Interrupted items stay in progress for the resume; none was blocked by the pause.
    expect(items.some((i) => i.status === 'in_progress')).toBe(true);
    expect(items.filter((i) => i.status === 'blocked')).toEqual([]);
    expect((await cases.listChecks(paused.caseId)).filter((c) => c.checkId.startsWith('item:'))).toEqual([]);
    expect((await cases.listObjectives(paused.caseId)).some((o) => o.status === 'NOT_MET')).toBe(false);
    const started = (await cases.listAudit(paused.caseId)).find((a) => a.stage === 'case.started');
    expect(started?.data.runOptions).toEqual({ maxCostUsd: 3, recon: false });

    const resumed = await run();
    expect(resumed.status).toBe('CONVERGED');
    expect((await cases.listWorkItems(paused.caseId)).every((i) => i.status === 'done')).toBe(true);
    expect((await cases.listAudit(paused.caseId)).map((a) => a.stage)).toContain('case.resumed');
  });

  it('cancels for good: the case ends CANCELLED and reports unfinished work', async () => {
    const { cases, run, signal } = pausable(3, 'cancel');
    const outcome = await run(signal);
    expect(outcome.status).toBe('CANCELLED');
    const rc = await cases.getCase(outcome.caseId);
    expect(rc).toMatchObject({ status: 'CANCELLED', stopReason: 'cancelled by alice' });
    expect(rc?.completedAt).toBeDefined();
    expect((await cases.listChecks(outcome.caseId)).some((c) => c.outcome === 'NOT_RUN')).toBe(true);
  });

  it('decides PAUSED before CANCELLED and names who asked', () => {
    const base = { items: [], round: 1, maxRounds: 6, roundsWithoutProgress: 0, parkedItems: new Set<string>() };
    expect(decideStop({ ...base, cancelled: false, paused: true, by: 'bob' })).toEqual({
      stop: 'PAUSED',
      reason: 'paused by bob',
    });
    expect(decideStop({ ...base, cancelled: true })?.reason).toBe('cancelled by the operator');
  });
});
