import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { applyPatchToRepository, fixFinding, runScan, type ScanRequest, silentLogger, verifyFix } from '@spinxsca/core';
import { imageRef, PINNED_IMAGES } from '@spinxsca/scanners';
import { afterEach, describe, expect, it } from 'vitest';
import { createAi, scriptedRemediation } from '../src/ai';
import { openEngine, scanDeps } from '../src/engine';

const ROOT = resolve(__dirname, '../../..');
const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const semgrepPresent = (() => {
  try {
    execFileSync('docker', ['image', 'inspect', imageRef(PINNED_IMAGES.semgrep)], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
})();

describe.runIf(semgrepPresent)('phase 2: remediation (docker)', () => {
  it('verifies a scripted patch by re-scan, keeps the repository untouched until applied, then verify-fix confirms', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'spx-fix-'));
    dirs.push(dir);
    cpSync(join(ROOT, 'evals/internal/001-sqli-express/src'), join(dir, 'src'), { recursive: true });
    const ai = createAi({ provider: 'scripted', effort: 'high', refusalFallback: 'default', maxCostUsdPerFinding: 1 });
    const engine = openEngine({
      scanRoot: join(dir, 'src'),
      stateDir: join(dir, 'state'),
      kbDir: join(dir, 'kb'),
      logger: silentLogger,
      ai: { provider: 'scripted', effort: 'high', refusalFallback: 'default', maxCostUsdPerFinding: 1 },
    });
    engine.scanners.splice(0, engine.scanners.length, ...engine.scanners.filter((s) => s.describe().id === 'semgrep'));
    try {
      const request: ScanRequest = {
        projectName: 't',
        mode: 'FULL',
        exclude: [],
        baseline: { kind: 'none' },
        reuseCache: false,
      };
      const scan = await runScan(scanDeps(engine), request);
      expect(scan.assessments).toHaveLength(2);
      const users = join(dir, 'src/routes/users.js');
      const before = readFileSync(users, 'utf8');

      // SPX-000001 is `const rows = await db.query(sql);` at line 10; parameterize it.
      scriptedRemediation.replacement =
        "  const rows = await db.query('SELECT id, email FROM users WHERE name = $1', [name]);";
      scriptedRemediation.lines = 1;
      const patchesDir = join(dir, 'state', 'patches');
      const deps = {
        scan: scanDeps(engine),
        remediator: ai.remediator,
        openWorkspace: async (stateDir: string) => {
          const engines: Array<ReturnType<typeof openEngine>> = [];
          return {
            deps: (sourceDir: string) => {
              const e = openEngine({
                scanRoot: sourceDir,
                stateDir,
                kbDir: join(stateDir, 'kb'),
                logger: silentLogger,
              });
              e.scanners.splice(0, e.scanners.length, ...e.scanners.filter((s) => s.describe().id === 'semgrep'));
              engines.push(e);
              return scanDeps(e);
            },
            close: () => {
              for (const e of engines) e.close();
            },
          };
        },
        runTests: async () => ({ status: 'not_available' as const, output: 'no test runner in fixture' }),
        patchesDir,
      };
      const result = await fixFinding(deps, 'SPX-000001');
      expect(result.status).toBe('rescan_passed');
      expect(result.verification.rescan).toBe('RESOLVED');
      expect(result.verification.newFindings).toEqual([]);
      expect(result.files).toEqual(['routes/users.js']);
      expect(result.diff).toContain(
        "+  const rows = await db.query('SELECT id, email FROM users WHERE name = $1', [name]);",
      );
      expect(readFileSync(users, 'utf8')).toBe(before);
      expect((await engine.repo.listAgentRuns({ findingId: 'SPX-000001' })).map((r) => r.role)).toEqual([
        'remediation',
      ]);

      // A patch that does not fix the issue is reported as failed.
      scriptedRemediation.replacement = '  const rows = await db.query(sql); // still vulnerable';
      const bad = await fixFinding(deps, 'SPX-000001');
      expect(bad.status).toBe('failed');
      expect(bad.verification.rescan).toBe('STILL_PRESENT');

      // Apply the good patch and confirm with verify-fix (targeted re-scan of the file).
      applyPatchToRepository(engine.source, patchesDir, result.patchId);
      expect(readFileSync(users, 'utf8')).not.toBe(before);
      const verified = await verifyFix(scanDeps(engine), 'SPX-000001');
      expect(verified.status).toBe('fixed');
      const other = await verifyFix(scanDeps(engine), 'SPX-000002');
      expect(other.status).toBe('still_vulnerable');
      writeFileSync(users, before);
    } finally {
      engine.close();
    }
  }, 300_000);
});
