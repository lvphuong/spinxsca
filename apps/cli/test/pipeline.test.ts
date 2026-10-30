import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  buildReportModel,
  type CandidateDraft,
  runScan,
  type ScannerAdapter,
  type ScannerResult,
  type ScanRequest,
  silentLogger,
} from '@spinxsca/core';
import type { ReconciliationState } from '@spinxsca/schemas';
import { afterEach, describe, expect, it } from 'vitest';
import { type Engine, openEngine, scanDeps } from '../src/engine';

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function workspace(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'spx-pipeline-'));
  dirs.push(dir);
  for (const [path, content] of Object.entries(files)) {
    execFileSync('mkdir', ['-p', join(dir, 'src', path, '..')]);
    writeFileSync(join(dir, 'src', path), content);
  }
  return dir;
}

/** Deterministic scanner: reports every line containing `db.query(` + string concatenation. */
class FakeSqlScanner implements ScannerAdapter {
  fail = false;
  describe() {
    return {
      id: 'fake-sql',
      adapterVersion: '1',
      toolVersion: '1',
      image: 'fake@sha256:0',
      capabilities: ['SAST' as const],
      languages: ['javascript'],
      scanModes: ['FULL' as const],
      outputs: ['NATIVE_JSON' as const],
      requiresNetwork: false,
      requiresBuild: false,
      resources: { cpus: 1, memoryMb: 128, timeoutSec: 10 },
    };
  }
  async ruleBundles() {
    return [{ id: 'fake', version: '1', digest: `sha256:${'1'.repeat(64)}` as const, ruleCount: 1 }];
  }
  applies() {
    return true;
  }
  async run(ctx: Parameters<ScannerAdapter['run']>[0]): Promise<ScannerResult> {
    if (this.fail) throw new Error('scanner crashed');
    const files = await ctx.source.listFiles({ exclude: [] });
    const drafts: CandidateDraft[] = [];
    for (const file of files) {
      const lines = ((await ctx.source.readText(file.path)) ?? '').split('\n');
      lines.forEach((line, i) => {
        if (/db\.query\([^)]*\+/.test(line)) {
          drafts.push({
            scanner: 'fake-sql',
            ruleId: 'fake.sqli',
            ruleFamily: 'sqli',
            category: 'SQL_INJECTION',
            cwe: ['CWE-89'],
            title: 'SQL injection',
            message: 'concatenated SQL',
            severityHint: 'HIGH',
            confidenceHint: 'MEDIUM',
            locations: [{ path: file.path, startLine: i + 1, endLine: i + 1, role: 'primary' }],
          });
        }
      });
    }
    const list = await ctx.artifacts.put(JSON.stringify(files.map((f) => f.path)), 'application/json');
    return {
      drafts,
      rawArtifacts: {},
      coverage: {
        scope: 'FULL',
        completeness: 'COMPLETE',
        files: { analyzed: files.length, total: files.length, listDigest: list.digest },
        languages: ['javascript'],
        rules: { executed: 1, bundleDigests: [`sha256:${'1'.repeat(64)}`], ids: ['fake.sqli'] },
        toolErrors: [],
      },
    };
  }
}

const request: ScanRequest = {
  projectName: 't',
  mode: 'FULL',
  exclude: [],
  baseline: { kind: 'auto' },
  reuseCache: false,
};

async function scan(engine: Engine): Promise<Map<string, ReconciliationState>> {
  const outcome = await runScan(scanDeps(engine), request);
  const assessments = await engine.repo.listAssessments(outcome.scan.scanId);
  return new Map(assessments.map((a) => [a.findingId, a.reconciliationState]));
}

const VULN_A = "db.query('SELECT * FROM a WHERE x = ' + req.query.x);";
const VULN_B = "db.query('DELETE FROM b WHERE y = ' + req.body.y);";

describe('scan pipeline (fake scanner)', () => {
  it('tracks identity through rescans, fixes, regressions and renames', async () => {
    const dir = workspace({
      'routes/a.js': `function listA(req) {\n  ${VULN_A}\n}\n`,
      'routes/b.js': `function deleteB(req) {\n  ${VULN_B}\n}\n`,
    });
    const scanner = new FakeSqlScanner();
    const engine = openEngine({
      scanRoot: join(dir, 'src'),
      stateDir: join(dir, 'state'),
      kbDir: join(dir, 'kb'),
      logger: silentLogger,
    });
    engine.scanners.splice(0, engine.scanners.length, scanner);
    try {
      expect(Object.fromEntries(await scan(engine))).toEqual({ 'SPX-000001': 'NEW', 'SPX-000002': 'NEW' });

      // Unchanged source keeps identity.
      expect(Object.fromEntries(await scan(engine))).toEqual({ 'SPX-000001': 'EXISTING', 'SPX-000002': 'EXISTING' });

      // Fix B: resolved because the scanner covered the file with the rule.
      writeFileSync(
        join(dir, 'src/routes/b.js'),
        "function deleteB(req) {\n  db.query('DELETE FROM b WHERE y = $1', [req.body.y]);\n}\n",
      );
      expect(Object.fromEntries(await scan(engine))).toEqual({ 'SPX-000001': 'EXISTING', 'SPX-000002': 'RESOLVED' });

      // Regression: the same code comes back and the old identity is reopened.
      writeFileSync(join(dir, 'src/routes/b.js'), `function deleteB(req) {\n  ${VULN_B}\n}\n`);
      expect(Object.fromEntries(await scan(engine))).toEqual({ 'SPX-000001': 'EXISTING', 'SPX-000002': 'REOPENED' });

      // Rename a.js -> accounts.js: same symbol and code shape, identity kept.
      renameSync(join(dir, 'src/routes/a.js'), join(dir, 'src/routes/accounts.js'));
      expect(Object.fromEntries(await scan(engine))).toEqual({ 'SPX-000001': 'EXISTING', 'SPX-000002': 'EXISTING' });

      // Scanner failure: nothing may be marked resolved.
      scanner.fail = true;
      const outcome = await runScan(scanDeps(engine), request);
      expect(outcome.scan.status).toBe('FAILED');
      const states = new Map(
        (await engine.repo.listAssessments(outcome.scan.scanId)).map((a) => [a.findingId, a.reconciliationState]),
      );
      expect(Object.fromEntries(states)).toEqual({ 'SPX-000001': 'NOT_REEVALUATED', 'SPX-000002': 'NOT_REEVALUATED' });
      const model = await buildReportModel(engine.repo, outcome.scan.scanId);
      expect(model.notReevaluated.map((e) => e.finding.findingId)).toEqual(['SPX-000001', 'SPX-000002']);
    } finally {
      engine.close();
    }
  });

  it('resumes an interrupted scan and refuses to resume after the source changed', async () => {
    const dir = workspace({ 'a.js': `function f(req) {\n  ${VULN_A}\n}\n` });
    const engine = openEngine({
      scanRoot: join(dir, 'src'),
      stateDir: join(dir, 'state'),
      kbDir: join(dir, 'kb'),
      logger: silentLogger,
    });
    engine.scanners.splice(0, engine.scanners.length, new FakeSqlScanner());
    try {
      const first = await runScan(scanDeps(engine), request);
      await engine.repo.updateScan(first.scan.scanId, { status: 'RUNNING' });
      const resumed = await runScan(scanDeps(engine), { ...request, resumeScanId: first.scan.scanId });
      expect(resumed.scan.scanId).toBe(first.scan.scanId);
      expect(resumed.scan.status).toBe('COMPLETED');
      writeFileSync(join(dir, 'src/a.js'), 'changed');
      await engine.repo.updateScan(first.scan.scanId, { status: 'RUNNING' });
      await expect(runScan(scanDeps(engine), { ...request, resumeScanId: first.scan.scanId })).rejects.toThrow(
        'source changed',
      );
    } finally {
      engine.close();
    }
  });
});

const dockerAvailable = (() => {
  try {
    execFileSync(
      'docker',
      [
        'image',
        'inspect',
        'semgrep/semgrep:1.182.1@sha256:451b3d875c00dac7ed5db5293e584a07de11449a409c10b3c2d2652f429630b6',
      ],
      { stdio: 'pipe' },
    );
    return true;
  } catch {
    return false;
  }
})();

describe.runIf(dockerAvailable)('scan pipeline (semgrep in docker)', () => {
  it('detects the SQL injections of eval case 001 and resolves a fixed one', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'spx-semgrep-'));
    dirs.push(dir);
    cpSync(resolve(__dirname, '../../../evals/internal/001-sqli-express/src'), join(dir, 'src'), { recursive: true });
    const engine = openEngine({
      scanRoot: join(dir, 'src'),
      stateDir: join(dir, 'state'),
      kbDir: join(dir, 'kb'),
      logger: silentLogger,
    });
    try {
      const first = await runScan(scanDeps(engine), request);
      expect(first.scan.status).toBe('COMPLETED');
      const model = await buildReportModel(engine.repo, first.scan.scanId);
      expect(
        model.present.map((e) => `${e.occurrence?.locations[0]?.path}:${e.occurrence?.locations[0]?.startLine}`),
      ).toEqual(['routes/users.js:10', 'routes/users.js:22']);
      const file = join(dir, 'src/routes/users.js');
      writeFileSync(
        file,
        readFileSync(file, 'utf8').replace(
          // biome-ignore lint/suspicious/noTemplateCurlyInString: literal source text being rewritten
          "await db.query(`DELETE FROM users WHERE email = '${req.body.email}'`);",
          "await db.query('DELETE FROM users WHERE email = $1', [req.body.email]);",
        ),
      );
      const second = await runScan(scanDeps(engine), request);
      const states = Object.fromEntries(
        (await engine.repo.listAssessments(second.scan.scanId)).map((a) => [a.findingId, a.reconciliationState]),
      );
      expect(states).toEqual({ 'SPX-000001': 'EXISTING', 'SPX-000002': 'RESOLVED' });
    } finally {
      engine.close();
    }
  }, 120_000);
});
