import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { buildReportModel, runScan, type ScanRequest, silentLogger } from '@spinxsca/core';
import { importOsvFiles, KbStore } from '@spinxsca/kb';
import { imageRef, PINNED_IMAGES } from '@spinxsca/scanners';
import { afterEach, describe, expect, it } from 'vitest';
import { openEngine, scanDeps } from '../src/engine';

const ROOT = resolve(__dirname, '../../..');
const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const imagesPresent = (() => {
  try {
    for (const image of Object.values(PINNED_IMAGES))
      execFileSync('docker', ['image', 'inspect', imageRef(image)], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
})();

const request: ScanRequest = {
  projectName: 't',
  mode: 'FULL',
  exclude: [],
  baseline: { kind: 'auto' },
  reuseCache: false,
};

function allFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? allFiles(path) : [path];
  });
}

describe.runIf(imagesPresent)('phase 1 scanners (docker)', () => {
  it('never persists secret values found by gitleaks', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'spx-secrets-'));
    dirs.push(dir);
    cpSync(join(ROOT, 'evals/internal/007-hardcoded-secret/src'), join(dir, 'src'), { recursive: true });
    const secrets =
      readFileSync(join(dir, 'src/settings.js'), 'utf8')
        .match(/"[A-Za-z0-9]{24,}"/g)
        ?.map((s) => s.slice(1, -1)) ?? [];
    expect(secrets.length).toBeGreaterThanOrEqual(3);
    const engine = openEngine({
      scanRoot: join(dir, 'src'),
      stateDir: join(dir, 'state'),
      kbDir: join(dir, 'kb'),
      logger: silentLogger,
    });
    try {
      const outcome = await runScan(scanDeps(engine), request);
      const model = await buildReportModel(engine.repo, outcome.scan.scanId);
      expect(model.present.filter((e) => e.finding.category === 'HARDCODED_SECRET')).toHaveLength(3);
      expect(model.present[0]?.evidence[0]?.excerpt).toContain('<REDACTED');
    } finally {
      engine.close();
    }
    const leaks = allFiles(join(dir, 'state')).filter((file) => {
      const bytes = readFileSync(file);
      return secrets.some((secret) => bytes.includes(Buffer.from(secret)));
    });
    expect(leaks).toEqual([]);
  }, 180_000);

  it('reports new advisories on unchanged code as NEW_ADVISORY in a dependency reassessment', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'spx-sca-'));
    dirs.push(dir);
    cpSync(join(ROOT, 'evals/internal/005-dep-cve-npm'), join(dir, 'src'), { recursive: true });
    const kbDir = join(dir, 'kb');
    const store = KbStore.open(kbDir);
    importOsvFiles(store, [join(ROOT, 'evals/fixtures/osv/npm/GHSA-p6mc-m468-83gw.json')], {
      authoritativeFor: ['npm'],
    });
    store.createSnapshot();
    const engine = openEngine({
      scanRoot: join(dir, 'src'),
      stateDir: join(dir, 'state'),
      kbDir,
      logger: silentLogger,
    });
    try {
      const first = await runScan(scanDeps(engine), request);
      expect(first.assessments.map((a) => a.reconciliationState)).toEqual(['NEW']);
      importOsvFiles(store, [join(ROOT, 'evals/fixtures/osv/npm')], { authoritativeFor: ['npm'] });
      store.createSnapshot();
      const second = await runScan(scanDeps(engine), { ...request, mode: 'DEPENDENCY_REASSESSMENT' });
      expect(second.scan.manifest.scannerBundle.scanners.map((s) => s.id)).toEqual(['osv-scanner']);
      const fresh = second.assessments.filter((a) => a.reconciliationState === 'NEW');
      expect(fresh).toHaveLength(2);
      expect(fresh.every((a) => a.changeCauses.includes('NEW_ADVISORY'))).toBe(true);
      expect(second.assessments.filter((a) => a.reconciliationState === 'EXISTING')).toHaveLength(1);
    } finally {
      engine.close();
      store.close();
    }
  }, 180_000);
});
