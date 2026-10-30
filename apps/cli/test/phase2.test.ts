import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { AgentInvestigator, loadPromptBundle, ScriptedProvider } from '@spinxsca/agent';
import { buildReportModel, type Investigator, runScan, type ScanRequest, silentLogger } from '@spinxsca/core';
import { imageRef, PINNED_IMAGES } from '@spinxsca/scanners';
import { afterEach, describe, expect, it } from 'vitest';
import { openEngine, scanDeps } from '../src/engine';

const ROOT = resolve(__dirname, '../../..');
const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const git = (cwd: string, ...args: string[]) =>
  execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args], {
    cwd,
    stdio: 'pipe',
  });
const semgrepPresent = (() => {
  try {
    execFileSync('docker', ['image', 'inspect', imageRef(PINNED_IMAGES.semgrep)], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
})();

describe.runIf(semgrepPresent)('phase 2: incremental scan (docker)', () => {
  it('scopes semgrep to the change impact and carries unchanged findings forward', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'spx-incr-'));
    dirs.push(dir);
    cpSync(join(ROOT, 'evals/internal/001-sqli-express/src'), join(dir, 'src'), { recursive: true });
    writeFileSync(
      join(dir, 'src/routes/reports.js'),
      [
        "const express = require('express');",
        'const router = express.Router();',
        "router.get('/reports', (req, res) => res.json([]));",
        'module.exports = router;',
        '',
      ].join('\n'),
    );
    git(dir, 'init', '-q', '-b', 'main');
    git(dir, 'add', '.');
    git(dir, 'commit', '-q', '-m', 'base');
    const engine = openEngine({
      scanRoot: join(dir, 'src'),
      stateDir: join(dir, 'state'),
      kbDir: join(dir, 'kb'),
      logger: silentLogger,
    });
    engine.scanners.splice(0, engine.scanners.length, ...engine.scanners.filter((s) => s.describe().id === 'semgrep'));
    try {
      const base: ScanRequest = {
        projectName: 't',
        mode: 'FULL',
        exclude: [],
        baseline: { kind: 'none' },
        reuseCache: false,
      };
      const full = await runScan(scanDeps(engine), base);
      expect(full.assessments.map((a) => a.reconciliationState)).toEqual(['NEW', 'NEW']);
      expect(full.tasks.map((t) => t.kind).sort()).toEqual(['INDEX', 'SCANNER']);
      const model = await buildReportModel(engine.repo, full.scan.scanId);
      expect(model.present[0]?.occurrence?.locations[0]?.symbolKey).toMatch(
        /^routes\/users\.js::<GET \/users\/search>/,
      );

      // Change an unrelated route: only that file is in scope; the SQLi findings are carried forward.
      writeFileSync(
        join(dir, 'src/routes/reports.js'),
        [
          "const express = require('express');",
          'const router = express.Router();',
          "router.get('/reports', (req, res) => res.json({ ok: true }));",
          'module.exports = router;',
          '',
        ].join('\n'),
      );
      const incremental = await runScan(scanDeps(engine), {
        ...base,
        mode: 'INCREMENTAL',
        diffBase: 'HEAD',
        baseline: { kind: 'auto' },
      });
      expect(incremental.scan.status).toBe('COMPLETED');
      expect(incremental.impact?.changedFiles).toEqual(['routes/reports.js']);
      expect(incremental.impact?.scope).toEqual(['routes/reports.js']);
      const semgrep = incremental.tasks.find((t) => t.scannerId === 'semgrep');
      expect(semgrep?.coverage?.scope).toBe('INCREMENTAL');
      expect(semgrep?.coverage?.files.analyzed).toBe(1);
      expect(incremental.assessments.map((a) => a.reconciliationState)).toEqual(['NOT_REEVALUATED', 'NOT_REEVALUATED']);

      // Fix one SQLi: that file is in scope, the fixed finding resolves, the other stays present.
      const users = join(dir, 'src/routes/users.js');
      writeFileSync(
        users,
        readFileSync(users, 'utf8')
          .replace(
            '"SELECT id, email FROM users WHERE name = \'" + name + "\'"',
            "'SELECT id, email FROM users WHERE name = $1', [name]",
          )
          .replace('await db.query(sql)', 'await db.query(sql, [name])'),
      );
      const fixed = await runScan(scanDeps(engine), {
        ...base,
        mode: 'INCREMENTAL',
        diffBase: 'HEAD',
        baseline: { kind: 'scan', scanId: full.scan.scanId },
      });
      const states = Object.fromEntries(fixed.assessments.map((a) => [a.findingId, a.reconciliationState]));
      expect(states).toEqual({ 'SPX-000001': 'RESOLVED', 'SPX-000002': 'EXISTING' });
      expect(fixed.assessments.find((a) => a.findingId === 'SPX-000001')?.changeCauses).toContain('CODE_CHANGE');
    } finally {
      engine.close();
    }
  }, 180_000);

  it('merges AI findings with scanner findings and keeps scanner candidates primary', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'spx-ai-std-'));
    dirs.push(dir);
    cpSync(join(ROOT, 'evals/internal/003-idor-nest/src'), join(dir, 'src'), { recursive: true });
    cpSync(join(ROOT, 'evals/internal/001-sqli-express/src/routes/users.js'), join(dir, 'src/legacy.js'));
    const engine = openEngine({
      scanRoot: join(dir, 'src'),
      stateDir: join(dir, 'state'),
      kbDir: join(dir, 'kb'),
      logger: silentLogger,
    });
    engine.scanners.splice(0, engine.scanners.length, ...engine.scanners.filter((s) => s.describe().id === 'semgrep'));
    const bola = {
      category: 'BROKEN_OBJECT_LEVEL_AUTHORIZATION',
      cwe: ['CWE-639'],
      title: 'Any authenticated user can read any order',
      summary: 'findOne loads any order by id.',
      confidence: 'HIGH',
      severity: 'HIGH',
      attacker: 'authenticated user',
      invariantViolated: 'users read only their own orders',
      locations: [{ path: 'orders/orders.controller.ts', startLine: 12, endLine: 14, role: 'primary' }],
      evidence: ['no ownership predicate'],
      counterevidence: [],
      remediation: 'scope by owner',
    };
    const sqliDuplicate = {
      ...bola,
      category: 'SQL_INJECTION',
      cwe: ['CWE-89'],
      title: 'SQL built from request input',
      locations: [{ path: 'legacy.js', startLine: 9, endLine: 10, role: 'primary' }],
    };
    const provider = () =>
      new ScriptedProvider([
        (request) =>
          request.tools.some((t) => t.name === 'submit_threat_model')
            ? {
                content: [
                  {
                    type: 'tool_use',
                    id: 'p',
                    name: 'submit_threat_model',
                    input: { summary: 's', trustBoundaries: [], packets: [], notes: [] },
                  },
                ],
              }
            : {
                content: [
                  {
                    type: 'tool_use',
                    id: 'a',
                    name: 'submit_investigation',
                    input: { findings: [bola, sqliDuplicate], resolvedQuestions: [], reviewedFiles: [], deferred: [] },
                  },
                ],
              },
      ]);
    const investigator: Investigator = new AgentInvestigator({
      provider,
      prompts: loadPromptBundle(join(ROOT, 'prompts')),
    });
    try {
      const outcome = await runScan(
        { ...scanDeps(engine), investigator },
        {
          projectName: 't',
          mode: 'FULL',
          exclude: [],
          baseline: { kind: 'none' },
          reuseCache: false,
          ai: { level: 'standard', maxFindings: 0, maxCostUsd: 1 },
        },
      );
      expect(outcome.ai?.investigated).toBe(2);
      const model = await buildReportModel(engine.repo, outcome.scan.scanId);
      const byCategory = Object.fromEntries(model.present.map((e) => [e.finding.category, e]));
      // Two scanner SQLi findings plus one AI-only BOLA finding; the AI SQLi overlapped a scanner finding and merged into it.
      expect(model.present).toHaveLength(3);
      const merged = model.present.find((e) => e.candidates.length === 2);
      expect(merged?.candidates.map((c) => c.scanner).sort()).toEqual(['ai', 'semgrep']);
      expect(merged?.occurrence?.ruleIds).toContain('spinxsca-core.js-sql-injection');
      expect(merged?.finding.title).toBe('SQL injection from HTTP request input');
      expect(byCategory.BROKEN_OBJECT_LEVEL_AUTHORIZATION?.candidates[0]?.scanner).toBe('ai');
      expect(byCategory.BROKEN_OBJECT_LEVEL_AUTHORIZATION?.occurrence?.locations[0]?.symbolKey).toBe(
        'orders/orders.controller.ts::OrdersController.findOne',
      );
      expect((await engine.repo.listAgentRuns({ scanId: outcome.scan.scanId })).map((r) => r.role)).toEqual([
        'planner',
        'auditor',
      ]);
    } finally {
      engine.close();
    }
  }, 180_000);
});

describe('finding lookup errors', () => {
  it('explains that a scan is needed when the state directory has no findings', async () => {
    const { requireFinding } = await import('../src/context');
    const dir = mkdtempSync(join(tmpdir(), 'spx-nofind-'));
    dirs.push(dir);
    const engine = openEngine({
      scanRoot: dir,
      stateDir: join(dir, 'state'),
      kbDir: join(dir, 'kb'),
      logger: silentLogger,
    });
    try {
      await expect(requireFinding(engine, 'SPX-000001', 'some/path')).rejects.toThrow(
        /no findings recorded in .*state\. Run `spinxsca scan some\/path` first/,
      );
    } finally {
      engine.close();
    }
  });
});
