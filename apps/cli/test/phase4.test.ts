import { execFileSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { cpSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { silentLogger } from '@spinxsca/core';
import { importOsvFiles, KbStore } from '@spinxsca/kb';
import { imageRef, PINNED_IMAGES } from '@spinxsca/scanners';
import { SpinxscaConfig } from '@spinxsca/schemas';
import { buildServer, RemoteWorker, registerWorker } from '@spinxsca/server';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { openEngine, scanDeps } from '../src/engine';

// biome-ignore lint/suspicious/noExplicitAny: API response bodies are inspected structurally in this test
type Json = any;
const ROOT = resolve(__dirname, '../../..');
const present = (image: string) => {
  try {
    execFileSync('docker', ['image', 'inspect', image], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
};
const dockerReady = present(imageRef(PINNED_IMAGES.semgrep)) && present(imageRef(PINNED_IMAGES['osv-scanner']));
const git = (cwd: string, ...args: string[]) =>
  execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args], {
    cwd,
    stdio: 'pipe',
  })
    .toString()
    .trim();
const config = {
  config: SpinxscaConfig.parse({
    version: 1,
    scan: { scanners: { gitleaks: { enabled: false }, trivy: { enabled: false } } },
  }),
};

describe.runIf(dockerReady)('phase 4: remote workers (docker)', () => {
  let dir: string;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'spx-phase4-'));
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('runs an on-prem pool scan on a remote worker through the control plane, with the same KB snapshot', async () => {
    const origin = join(dir, 'origin');
    cpSync(join(ROOT, 'evals/internal/001-sqli-express/src'), origin, { recursive: true });
    cpSync(join(ROOT, 'evals/internal/005-dep-cve-npm/package.json'), join(origin, 'package.json'));
    cpSync(join(ROOT, 'evals/internal/005-dep-cve-npm/package-lock.json'), join(origin, 'package-lock.json'));
    git(origin, 'init', '-q', '-b', 'main');
    git(origin, 'add', '.');
    git(origin, 'commit', '-q', '-m', 'init');

    const kbDir = join(dir, 'kb');
    const store = KbStore.open(kbDir);
    importOsvFiles(store, [join(ROOT, 'evals/fixtures/osv/npm')], { authoritativeFor: ['npm'] });
    const kbSnapshot = store.createSnapshot();
    store.close();

    const server = buildServer({
      dataDir: join(dir, 'control'),
      kbDir,
      logger: silentLogger,
      kbSyncIntervalMinutes: 0,
      engines: ({ sourceDir, stateDir }) => {
        const engine = openEngine({ scanRoot: sourceDir, stateDir, kbDir, config, logger: silentLogger });
        return { deps: scanDeps(engine), close: () => engine.close() };
      },
    });
    const fetchApp = ((url: string | URL, init?: RequestInit) => server.app.request(String(url), init)) as typeof fetch;
    const admin = server.registry.createToken('admin', 'admin', new Date()).token;
    const api = async (path: string, method = 'GET', json?: unknown) =>
      (await (
        await server.app.request(path, {
          method,
          headers: { authorization: `Bearer ${admin}`, 'content-type': 'application/json' },
          ...(json ? { body: JSON.stringify(json) } : {}),
        })
      ).json()) as Json;
    try {
      const project = await api('/v1/projects', 'POST', {
        name: 'onprem-app',
        source: { kind: 'git', url: origin },
        workerPool: 'onprem',
      });
      const payload = JSON.stringify({ ref: 'refs/heads/main', after: git(origin, 'rev-parse', 'main') });
      await server.app.request(`/v1/webhooks/github/${project.projectId}`, {
        method: 'POST',
        body: payload,
        headers: {
          'x-github-event': 'push',
          'x-hub-signature-256': `sha256=${createHmac('sha256', project.webhookSecret).update(payload).digest('hex')}`,
        },
      });
      // The control plane's own worker does not serve the on-prem pool.
      expect(await server.worker.runOnce()).toBeUndefined();

      const { provisioningToken } = await api('/v1/workers/provision', 'POST', { pools: ['onprem'] });
      const workerConfig = await registerWorker({
        server: 'http://control',
        provisioningToken,
        name: 'onprem-1',
        fetch: fetchApp,
      });
      const workerDir = join(dir, 'worker');
      const worker: RemoteWorker = new RemoteWorker({
        config: workerConfig,
        dataDir: workerDir,
        logger: silentLogger,
        fetch: fetchApp,
        engines: ({ sourceDir, stateDir, repo, artifacts }) => {
          const engine = openEngine({
            scanRoot: sourceDir,
            stateDir,
            kbDir: worker.kbDir,
            config,
            logger: silentLogger,
            ...(repo ? { repo } : {}),
            ...(artifacts ? { artifacts } : {}),
          });
          return { deps: scanDeps(engine), close: () => engine.close() };
        },
      });
      const job = await worker.runOnce();
      expect(job).toBeTruthy();
      const stored = server.registry.job((job as { jobId: string }).jobId);
      expect(stored).toMatchObject({ status: 'SUCCEEDED', pool: 'onprem', workerId: workerConfig.workerId });
      expect(stored?.result?.tasks).toEqual(expect.arrayContaining(['semgrep', 'osv-scanner', 'INDEX']));

      // Results live on the control plane: findings, branch status, and the scan pinned to the same KB snapshot.
      const findings = (await api(`/v1/projects/${project.projectId}/findings?branch=main`)) as Array<{
        category: string;
        branch: { state: string };
      }>;
      expect(findings.map((f) => f.category).sort()).toEqual([
        'SQL_INJECTION',
        'SQL_INJECTION',
        'VULNERABLE_DEPENDENCY',
        'VULNERABLE_DEPENDENCY',
        'VULNERABLE_DEPENDENCY',
      ]);
      const scans = (await api(`/v1/projects/${project.projectId}/scans`)) as Array<{ scanId: string; branch: string }>;
      const scan = await server.states.get(project.projectId).repo.getScan(scans[0]?.scanId as string);
      expect(scan?.manifest.knowledgeBase?.snapshotId).toBe(kbSnapshot.snapshotId);
      expect(scans[0]?.branch).toBe('main');
      // The worker kept no project database of its own.
      expect(() =>
        execFileSync('ls', [join(workerDir, 'state', project.projectId, 'state.db')], { stdio: 'pipe' }),
      ).toThrow();
    } finally {
      await server.close();
    }
  }, 600_000);

  it.runIf(present('postgres:17-alpine'))(
    'keeps project state in PostgreSQL schemas',
    async () => {
      const container = execFileSync('docker', [
        'run',
        '-d',
        '--rm',
        '-e',
        'POSTGRES_PASSWORD=spx',
        '-p',
        '127.0.0.1::5432',
        'postgres:17-alpine',
      ])
        .toString()
        .trim();
      const port = execFileSync('docker', ['port', container, '5432/tcp']).toString().trim().split(':').pop();
      const databaseUrl = `postgres://postgres:spx@127.0.0.1:${port}/postgres`;
      const probe = new pg.Pool({ connectionString: databaseUrl });
      try {
        for (let i = 0; i < 60; i++) {
          try {
            await probe.query('SELECT 1');
            break;
          } catch {
            await new Promise((r) => setTimeout(r, 500));
          }
        }
        const origin = join(dir, 'origin-pg');
        cpSync(join(ROOT, 'evals/internal/001-sqli-express/src'), origin, { recursive: true });
        git(origin, 'init', '-q', '-b', 'main');
        git(origin, 'add', '.');
        git(origin, 'commit', '-q', '-m', 'init');
        const kbDir = join(dir, 'kb-pg');
        const server = buildServer({
          dataDir: join(dir, 'control-pg'),
          kbDir,
          databaseUrl,
          logger: silentLogger,
          kbSyncIntervalMinutes: 0,
          engines: ({ sourceDir, stateDir, repo, artifacts }) => {
            const engine = openEngine({
              scanRoot: sourceDir,
              stateDir,
              kbDir,
              config,
              logger: silentLogger,
              ...(repo ? { repo } : {}),
              ...(artifacts ? { artifacts } : {}),
            });
            return { deps: scanDeps(engine), close: () => engine.close() };
          },
        });
        const admin = server.registry.createToken('admin', 'admin', new Date()).token;
        const api = async (path: string, method = 'GET', json?: unknown) =>
          (await (
            await server.app.request(path, {
              method,
              headers: { authorization: `Bearer ${admin}`, 'content-type': 'application/json' },
              ...(json ? { body: JSON.stringify(json) } : {}),
            })
          ).json()) as Json;
        try {
          const project = await api('/v1/projects', 'POST', { name: 'pg-app', source: { kind: 'git', url: origin } });
          await api(`/v1/projects/${project.projectId}/scans`, 'POST', { branch: 'main' });
          const job = await server.worker.runOnce();
          expect(job).toMatchObject({ status: 'SUCCEEDED' });
          const findings = (await api(`/v1/projects/${project.projectId}/findings?branch=main`)) as Array<{
            category: string;
            branch: { state: string };
          }>;
          expect(findings.map((f) => [f.category, f.branch.state])).toEqual([
            ['SQL_INJECTION', 'OPEN'],
            ['SQL_INJECTION', 'OPEN'],
          ]);
          const schema = `spx_${project.projectId.toLowerCase()}`;
          const rows = await probe.query(`SELECT count(*)::int AS n FROM "${schema}".findings`);
          expect(rows.rows[0]?.n).toBe(2);
          expect(() =>
            execFileSync('ls', [join(dir, 'control-pg', 'projects', project.projectId, 'state', 'state.db')], {
              stdio: 'pipe',
            }),
          ).toThrow();
          expect(
            (await api(`/v1/projects/${project.projectId}/gate?branch=main`)).checks.map((c: { id: string }) => c.id),
          ).toContain('scan-age');
        } finally {
          await server.close();
        }
      } finally {
        await probe.end();
        execFileSync('docker', ['rm', '-f', container], { stdio: 'pipe' });
      }
    },
    600_000,
  );
});
