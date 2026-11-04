import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  type CandidateDraft,
  evaluatePolicy,
  runScan,
  type ScannerAdapter,
  type ScannerResult,
  silentLogger,
  verifyChain,
} from '@spinxsca/core';
import { SpinxscaConfig } from '@spinxsca/schemas';
import { afterEach, describe, expect, it } from 'vitest';
import { autonomyConfig, createReviewer, reviewPorts } from '../src/autonomy';
import type { LoadedConfig } from '../src/config';
import { openEngine, scanDeps } from '../src/engine';

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

class FakeSqlScanner implements ScannerAdapter {
  describe() {
    return {
      id: 'fake-sql',
      adapterVersion: '1',
      toolVersion: '1',
      image: `fake@sha256:${'0'.repeat(64)}`,
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

describe('spinxsca review (scripted provider, fake scanner)', () => {
  it('runs an autonomous case inside the scan and applies its verdicts before commit', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'spx-review-'));
    dirs.push(dir);
    mkdirSync(join(dir, 'src', 'routes'), { recursive: true });
    writeFileSync(
      join(dir, 'src', 'routes', 'users.js'),
      [
        "const express = require('express');",
        "const db = require('../db');",
        'const router = express.Router();',
        "router.get('/users/:id', (req, res) => {",
        "  db.query('SELECT * FROM users WHERE id = ' + req.params.id).then((r) => res.json(r));",
        '});',
        'module.exports = router;',
      ].join('\n'),
    );
    writeFileSync(join(dir, 'src', 'db.js'), 'module.exports = { query: async () => [] };\n');
    const loaded: LoadedConfig = {
      config: SpinxscaConfig.parse({
        version: 1,
        ai: { level: 'deep', provider: 'scripted', autonomy: { mode: 'supervised' } },
      }),
    };
    const engine = openEngine({
      scanRoot: join(dir, 'src'),
      stateDir: join(dir, 'state'),
      kbDir: join(dir, 'kb'),
      logger: silentLogger,
      config: loaded,
    });
    engine.scanners.splice(0, engine.scanners.length, new FakeSqlScanner());
    try {
      const config = autonomyConfig(loaded, { unattended: true }, 5);
      expect(config).toMatchObject({ mode: 'supervised', attended: false, l3: false, reviewer: 'on' });
      const reviewer = createReviewer({
        ai: { provider: 'scripted', effort: 'low', refusalFallback: 'off', maxCostUsdPerFinding: 5 },
        loaded,
        config,
      });
      const outcome = await runScan(scanDeps(engine, { reviewer, ports: reviewPorts(engine, loaded) }), {
        projectName: 't',
        mode: 'FULL',
        exclude: [],
        baseline: { kind: 'auto' },
        reuseCache: false,
        ai: { level: 'deep', maxFindings: 20, maxCostUsd: 5 },
      });
      expect(outcome.scan.status).toBe('COMPLETED');
      expect(outcome.scan.manifest.aiPolicy).toMatchObject({
        level: 'deep',
        provider: 'scripted',
        autonomyDigest: reviewer.policyDigest,
      });
      expect(outcome.ai?.review).toMatchObject({ status: 'CONVERGED', verdicts: 1, applied: 1 });
      const [assessment] = outcome.assessments;
      expect(assessment).toMatchObject({
        assessedBy: 'agent:review/scripted',
        verificationLevel: 'L2_CONTEXT',
        severity: 'HIGH',
        severityBaseline: 'HIGH',
      });
      expect(assessment?.attackPath?.source).toBe('request data');
      expect(evaluatePolicy(outcome.assessments, { failOnSeverity: 'HIGH', newFindingsOnly: true }).passed).toBe(false);

      const cases = engine.cases;
      if (!cases) throw new Error('expected a case store');
      const [rc] = await cases.listCases({ projectId: outcome.scan.projectId });
      if (!rc) throw new Error('expected a case');
      expect(rc).toMatchObject({ status: 'CONVERGED', scanId: outcome.scan.scanId, attended: false });
      expect(verifyChain(await cases.listAudit(rc.caseId)).ok).toBe(true);
      const runs = await engine.repo.listAgentRuns({ scanId: outcome.scan.scanId });
      expect(runs.some((r) => r.personaId === 'validator' && r.caseId === rc.caseId)).toBe(true);
      // The code index found the route, so a threat packet was seeded for it.
      expect((await cases.listWorkItems(rc.caseId)).some((i) => i.kind === 'THREAT_PACKET')).toBe(true);
    } finally {
      engine.close();
    }
  }, 60_000);
});
