import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type {
  CandidateDraft,
  MapOutput,
  MapReduceInvestigator,
  ReduceOutput,
  ScannerAdapter,
  ScannerResult,
  ScanRequest,
} from '@spinxsca/core';
import { runScan, silentLogger } from '@spinxsca/core';
import type { AgentRunRecord, AiFinding } from '@spinxsca/schemas';
import { afterEach, describe, expect, it } from 'vitest';
import { type Engine, openEngine, scanDeps } from '../src/engine';
import { generateScaleFixture } from '../src/eval/scale-fixture';

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function workspace(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'spx-phase7-'));
  dirs.push(dir);
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, 'src', path)), { recursive: true });
    writeFileSync(join(dir, 'src', path), content);
  }
  return dir;
}

/** A scanner that finds nothing but keeps the scan's scanner coverage complete. */
class NoopScanner implements ScannerAdapter {
  describe() {
    return {
      id: 'noop',
      adapterVersion: '1',
      toolVersion: '1',
      image: 'noop@sha256:0',
      capabilities: ['SAST' as const],
      languages: ['javascript'],
      scanModes: ['FULL' as const],
      outputs: ['NATIVE_JSON' as const],
      requiresNetwork: false,
      requiresBuild: false,
      resources: { cpus: 1, memoryMb: 64, timeoutSec: 5 },
    };
  }
  async ruleBundles() {
    return [{ id: 'noop', version: '1', digest: `sha256:${'2'.repeat(64)}` as const, ruleCount: 0 }];
  }
  applies() {
    return true;
  }
  async run(ctx: Parameters<ScannerAdapter['run']>[0]): Promise<ScannerResult> {
    const files = await ctx.source.listFiles({ exclude: [] });
    const list = await ctx.artifacts.put(JSON.stringify(files.map((f) => f.path)), 'application/json');
    return {
      drafts: [],
      rawArtifacts: {},
      coverage: {
        scope: 'FULL',
        completeness: 'COMPLETE',
        files: { analyzed: files.length, total: files.length, listDigest: list.digest },
        languages: ['javascript'],
        toolErrors: [],
      },
    };
  }
}

const run = (): AgentRunRecord => ({
  agentRunId: `run_${Math.random().toString(36).slice(2, 10)}`,
  role: 'mapper',
  provider: 'fake',
  model: 'fake',
  modelsUsed: ['fake'],
  promptBundleDigest: `sha256:${'3'.repeat(64)}`,
  status: 'COMPLETED',
  usage: { inputTokens: 1, outputTokens: 1, cacheReadTokens: 0, cacheWriteTokens: 0 },
  steps: [],
  startedAt: new Date().toISOString(),
  completedAt: new Date().toISOString(),
});

/** Fake map/reduce: one finding per owned file with `db.query(`; a chosen shard module fails. */
class FakeMapReduce implements MapReduceInvestigator {
  readonly info = {
    provider: 'fake',
    model: 'fake',
    promptBundleDigest: `sha256:${'3'.repeat(64)}` as const,
    policyVersion: 'test',
    mapModel: 'fake-map',
    reduceModel: 'fake-reduce',
  };
  failModule: string | undefined;
  readonly mapped: string[] = [];
  mapEffectiveWindow() {
    return 24_000;
  }
  mapWorkers() {
    return 3;
  }
  async recon() {
    return {
      groundTruth: {
        archetype: 'hybrid' as const,
        archetypeNote: 'fake',
        trustClaims: [],
        invariants: [],
        baselines: [],
        families: [],
        carveouts: [],
        residualUnknowns: [],
        notes: [],
      },
      summary: 'fake',
      runs: [{ ...run(), role: 'recon' as const }],
      costUsd: 0,
      deferred: [],
      infraFailures: [],
    };
  }
  async map(
    subject: Parameters<MapReduceInvestigator['map']>[0],
    source: Parameters<MapReduceInvestigator['map']>[1],
  ): Promise<MapOutput> {
    this.mapped.push(subject.shard.shardId);
    if (this.failModule && subject.shard.module === this.failModule) throw new Error('worker exploded');
    const findings: AiFinding[] = [];
    for (const f of subject.shard.files) {
      const lines = ((await source.readText(f.path)) ?? '').split('\n');
      const line = lines.findIndex((l) => l.includes('db.query('));
      if (line < 0) continue;
      findings.push({
        category: 'SQL_INJECTION',
        cwe: ['CWE-89'],
        title: `SQL injection in ${f.path}`,
        summary: 'concatenated',
        confidence: 'HIGH',
        severity: 'HIGH',
        attacker: 'anyone',
        invariantViolated: 'parameterised queries',
        claim: `${f.path} builds SQL by concatenation`,
        preconditions: [],
        capabilitiesGained: [],
        proofObligations: [],
        threatModelClass: 'real_bug',
        locations: [{ path: f.path, startLine: line + 1, endLine: line + 1, role: 'primary' }],
        evidence: [`${f.path}:${line + 1}`],
        counterevidence: [],
        remediation: 'parameters',
      });
    }
    return {
      findings,
      invariantResults: [],
      variantLog: [],
      reviewedFiles: subject.shard.files.map((f) => f.path),
      deferred: [],
      run: run(),
      costUsd: 0.01,
    };
  }
  async reduce(input: Parameters<MapReduceInvestigator['reduce']>[0]): Promise<ReduceOutput> {
    const drafts: CandidateDraft[] = input.maps
      .flatMap((m) => m.findings)
      .map((f) => ({
        scanner: 'ai',
        ruleId: 'ai.mapper.sql_injection',
        ruleFamily: 'sql_injection',
        category: f.category,
        cwe: f.cwe,
        title: f.title,
        message: f.summary,
        severityHint: f.severity,
        confidenceHint: f.confidence,
        locations: f.locations,
      }));
    return {
      drafts,
      chains: [],
      run: { ...run(), role: 'reducer' },
      costUsd: 0,
      deferred: [],
      coverage: { invariantGaps: [], invariantTotal: 0, memberGaps: [], memberTotal: 0 },
    };
  }
}

const VULN = (table: string) =>
  `export function get(req) {\n  return db.query("select * from ${table} where id = " + req.params.id);\n}\n`;
const request = (mr: FakeMapReduce): ScanRequest => ({
  projectName: 'p7',
  mode: 'FULL',
  exclude: [],
  baseline: { kind: 'auto' },
  reuseCache: true,
  ai: {
    level: 'standard',
    maxFindings: 20,
    maxCostUsd: 5,
    sharding: { enabled: 'on', maxFilesPerShard: 2 },
    mapWorkers: mr.mapWorkers(),
  },
});

function openP7(dir: string): Engine {
  const engine = openEngine({
    scanRoot: join(dir, 'src'),
    stateDir: join(dir, 'state'),
    kbDir: join(dir, 'kb'),
    logger: silentLogger,
  });
  engine.scanners.splice(0, engine.scanners.length, new NoopScanner());
  return engine;
}

describe('phase 7: sharded investigation (fake map/reduce)', () => {
  it('plans shards, marks a failed shard as not run, and reuses unchanged shards on the next scan', async () => {
    const dir = workspace({
      'orders/a.js': VULN('orders'),
      'orders/b.js': VULN('order_items'),
      'users/a.js': VULN('users'),
      'users/b.js': VULN('sessions'),
      'util/clean.js': 'export const x = 1;\n',
    });
    const engine = openP7(dir);
    try {
      const mr = new FakeMapReduce();
      mr.failModule = 'users';
      const deps = { ...scanDeps(engine), mapReduce: mr };
      const first = await runScan(deps, request(mr));
      expect(first.ai?.shards).toMatchObject({ planned: 2, completed: 1, failed: 1, reused: 0 });
      expect(first.scan.status).toBe('PARTIAL');
      expect(first.scan.error).toMatch(/ai-shard:shard-\d{4} NOT_RUN/);
      expect(first.assessments).toHaveLength(2);
      expect(mr.mapped).toHaveLength(2);

      // Second scan: the failed shard runs again, the succeeded one is reused from the first scan.
      mr.failModule = undefined;
      mr.mapped.length = 0;
      const second = await runScan({ ...scanDeps(engine), mapReduce: mr }, request(mr));
      expect(second.scan.status).toBe('COMPLETED');
      expect(second.ai?.shards).toMatchObject({ planned: 2, completed: 2, failed: 0, reused: 1 });
      expect(mr.mapped).toHaveLength(1);
      expect(second.assessments).toHaveLength(4);

      // Changing one file re-runs only the shard that owns it.
      writeFileSync(join(dir, 'src/orders/a.js'), VULN('orders_v2'));
      mr.mapped.length = 0;
      const third = await runScan({ ...scanDeps(engine), mapReduce: mr }, request(mr));
      expect(third.ai?.shards).toMatchObject({ planned: 2, completed: 2, reused: 1 });
      expect(mr.mapped).toHaveLength(1);
      const tasks = third.tasks.filter((t) => t.name === 'ai-shard');
      expect(tasks).toHaveLength(2);
      expect(tasks.every((t) => t.coverage?.reviewedSurfaces?.length === 2)).toBe(true);
    } finally {
      engine.close();
    }
  });
});

describe('phase 7: scale fixture and scripted sharded path', () => {
  it('generates the same fixture for the same seed and plants findings the planner can see', async () => {
    const a = mkdtempSync(join(tmpdir(), 'spx-scale-a-'));
    const b = mkdtempSync(join(tmpdir(), 'spx-scale-b-'));
    dirs.push(a, b);
    const fa = generateScaleFixture(a, { files: 60, loc: 6_000, planted: 6, seed: 3 });
    const fb = generateScaleFixture(b, { files: 60, loc: 6_000, planted: 6, seed: 3 });
    expect(fa).toEqual(fb);
    expect(fa.files).toBeGreaterThanOrEqual(60);
    expect(fa.loc).toBeGreaterThanOrEqual(6_000);
    expect(fa.planted.length).toBe(6);
    expect(new Set(fa.planted.map((p) => p.kind)).size).toBeGreaterThanOrEqual(4);
    const listed = readdirSync(a, { recursive: true }).filter((f) => String(f).match(/\.(js|ts|py)$/));
    expect(listed.length).toBe(fa.files);
    for (const p of fa.planted) {
      const lines = readFileSync(join(a, p.path), 'utf8').split('\n');
      expect(lines.length).toBeGreaterThanOrEqual(p.lines[1]);
    }
    expect(readFileSync(join(a, 'README.md'), 'utf8')).toContain('seed 3');
  });

  it('runs the scripted map/reduce end to end on a generated repository', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'spx-scale-run-'));
    dirs.push(dir);
    mkdirSync(join(dir, 'src'));
    const fixture = generateScaleFixture(join(dir, 'src'), { files: 40, loc: 3_000, planted: 4, seed: 11 });
    const engine = openEngine({
      scanRoot: join(dir, 'src'),
      stateDir: join(dir, 'state'),
      kbDir: join(dir, 'kb'),
      logger: silentLogger,
      ai: { provider: 'scripted', effort: 'low', refusalFallback: 'off', maxCostUsdPerFinding: 1 },
    });
    engine.scanners.splice(0, engine.scanners.length, new NoopScanner());
    try {
      const outcome = await runScan(scanDeps(engine), {
        projectName: 'scale',
        mode: 'FULL',
        exclude: [],
        baseline: { kind: 'none' },
        reuseCache: false,
        ai: { level: 'standard', maxFindings: 50, maxCostUsd: 5, sharding: { enabled: 'on', maxFilesPerShard: 4 } },
      });
      expect(outcome.scan.status).toBe('COMPLETED');
      expect(outcome.ai?.shards?.planned).toBeGreaterThan(1);
      expect(outcome.ai?.shards?.failed).toBe(0);
      const sql = fixture.planted.filter((p) => p.kind === 'raw-sql-concat');
      const found = (await engine.repo.listOccurrences(outcome.scan.scanId)).map((o) => o.locations[0]?.path ?? '');
      for (const p of sql) expect(found.some((path) => path.endsWith(p.path.split('/').pop() as string))).toBe(true);
    } finally {
      engine.close();
    }
  });
});
