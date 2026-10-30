import { execFileSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { silentLogger } from '@spinxsca/core';
import { importOsvFiles, KbStore, syncKev } from '@spinxsca/kb';
import { imageRef, PINNED_IMAGES } from '@spinxsca/scanners';
import { SpinxscaConfig } from '@spinxsca/schemas';
import { buildServer } from '@spinxsca/server';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { openEngine, scanDeps } from '../src/engine';

const ROOT = resolve(__dirname, '../../..');
const OSV = join(ROOT, 'evals/fixtures/osv/npm');
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

describe.runIf(dockerReady)('phase 3: service, reassessment, branch status, release gate (docker)', () => {
  let dir: string;
  let receiver: Server;
  const events: Array<Record<string, unknown>> = [];
  let now = new Date();
  const clock = { now: () => now };

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'spx-phase3-'));
    receiver = createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => {
        body += chunk;
      });
      req.on('end', () => {
        events.push({
          ...(JSON.parse(body) as Record<string, unknown>),
          signature: req.headers['x-spinxsca-signature'],
        });
        res.end('ok');
      });
    });
    await new Promise<void>((r) => receiver.listen(0, '127.0.0.1', () => r()));
  });
  afterAll(async () => {
    await new Promise<void>((r) => receiver.close(() => r()));
    rmSync(dir, { recursive: true, force: true });
  });

  it('meets Milestone C: reassessment without SAST, FIXED on main / OPEN on develop, stale-scan gate', async () => {
    // Origin repositories: "shop" (Express SQLi + lodash 4.17.15) and "other" (left-pad only).
    const shop = join(dir, 'origin-shop');
    cpSync(join(ROOT, 'evals/internal/001-sqli-express/src'), shop, { recursive: true });
    cpSync(join(ROOT, 'evals/internal/005-dep-cve-npm/package.json'), join(shop, 'package.json'));
    cpSync(join(ROOT, 'evals/internal/005-dep-cve-npm/package-lock.json'), join(shop, 'package-lock.json'));
    git(shop, 'init', '-q', '-b', 'main');
    git(shop, 'add', '.');
    git(shop, 'commit', '-q', '-m', 'shop');
    git(shop, 'branch', 'develop');
    const other = join(dir, 'origin-other');
    cpSync(join(ROOT, 'evals/internal/004-secure-no-vuln/src'), other, { recursive: true });
    writeFileSync(
      join(other, 'package.json'),
      JSON.stringify({ name: 'other', version: '1.0.0', dependencies: { 'left-pad': '1.3.0' } }),
    );
    writeFileSync(
      join(other, 'package-lock.json'),
      JSON.stringify({
        name: 'other',
        version: '1.0.0',
        lockfileVersion: 3,
        requires: true,
        packages: {
          '': { name: 'other', version: '1.0.0', dependencies: { 'left-pad': '1.3.0' } },
          'node_modules/left-pad': { version: '1.3.0' },
        },
      }),
    );
    git(other, 'init', '-q', '-b', 'main');
    git(other, 'add', '.');
    git(other, 'commit', '-q', '-m', 'other');

    // Knowledge base without GHSA-29mw-wpgm-hmr9 (lodash, CVE-2020-28500): that advisory arrives later.
    const kbDir = join(dir, 'kb');
    const initial = join(dir, 'osv-initial');
    cpSync(OSV, initial, { recursive: true });
    rmSync(join(initial, 'GHSA-29mw-wpgm-hmr9.json'));
    const store = KbStore.open(kbDir);
    importOsvFiles(store, [initial], { authoritativeFor: ['npm'] });
    store.createSnapshot();
    store.close();

    const config = {
      config: SpinxscaConfig.parse({
        version: 1,
        scan: { scanners: { gitleaks: { enabled: false }, trivy: { enabled: false } } },
      }),
    };
    const server = buildServer({
      dataDir: join(dir, 'data'),
      kbDir,
      logger: silentLogger,
      clock,
      kbSyncIntervalMinutes: 0,
      notifyUrls: [`http://127.0.0.1:${(receiver.address() as AddressInfo).port}/hook`],
      notifySecret: 'notify-secret',
      gatePolicy: { maxScanAgeHours: 72, failOnSeverity: 'CRITICAL', blockKev: true, requireCompleteCoverage: false },
      engines: ({ sourceDir, stateDir }) => {
        const engine = openEngine({ scanRoot: sourceDir, stateDir, kbDir, config, logger: silentLogger });
        return { deps: scanDeps(engine), close: () => engine.close() };
      },
      // The "new CVE" arrives: the lodash advisory plus a KEV catalogue that lists it.
      kbSync: async (kb) => {
        importOsvFiles(kb.store, [join(OSV, 'GHSA-29mw-wpgm-hmr9.json')], { authoritativeFor: ['npm'] });
        const kev = {
          catalogVersion: '2026.10.30',
          dateReleased: '2026-10-30T00:00:00.000Z',
          vulnerabilities: [
            {
              cveID: 'CVE-2020-28500',
              dateAdded: '2026-10-30',
              dueDate: '2026-11-20',
              knownRansomwareCampaignUse: 'Unknown',
            },
          ],
        };
        return {
          kev: await syncKev(kb.store, {
            fetch: (async () => new Response(JSON.stringify(kev))) as unknown as typeof fetch,
          }),
        };
      },
    });
    const admin = server.registry.createToken('admin', 'admin', now).token;
    const api = async (path: string, init: { method?: string; json?: unknown } = {}) => {
      const res = await server.app.request(path, {
        method: init.method ?? 'GET',
        headers: { authorization: `Bearer ${admin}`, 'content-type': 'application/json' },
        ...(init.json !== undefined ? { body: JSON.stringify(init.json) } : {}),
      });
      // biome-ignore lint/suspicious/noExplicitAny: API responses are inspected structurally in this test
      return { status: res.status, body: (await res.json()) as any };
    };
    const drain = async () => {
      const done = [];
      for (let job = await server.worker.runOnce(); job; job = await server.worker.runOnce()) done.push(job);
      return done;
    };
    const push = async (projectId: string, secret: string, repo: string, branch: string) => {
      const payload = JSON.stringify({ ref: `refs/heads/${branch}`, after: git(repo, 'rev-parse', branch) });
      const res = await server.app.request(`/v1/webhooks/github/${projectId}`, {
        method: 'POST',
        body: payload,
        headers: {
          'x-github-event': 'push',
          'x-hub-signature-256': `sha256=${createHmac('sha256', secret).update(payload).digest('hex')}`,
        },
      });
      expect(res.status).toBe(202);
    };

    try {
      const shopProject = (
        await api('/v1/projects', { method: 'POST', json: { name: 'shop', source: { kind: 'git', url: shop } } })
      ).body;
      const otherProject = (
        await api('/v1/projects', { method: 'POST', json: { name: 'other', source: { kind: 'git', url: other } } })
      ).body;
      await push(shopProject.projectId, shopProject.webhookSecret, shop, 'main');
      await push(shopProject.projectId, shopProject.webhookSecret, shop, 'develop');
      await push(otherProject.projectId, otherProject.webhookSecret, other, 'main');
      const first = await drain();
      expect(first.map((j) => [j.kind, j.status, j.error ?? ''])).toEqual([
        ['SCAN', 'SUCCEEDED', ''],
        ['SCAN', 'SUCCEEDED', ''],
        ['SCAN', 'SUCCEEDED', ''],
      ]);

      // Fix the first SQL injection on main only.
      const users = join(shop, 'routes/users.js');
      git(shop, 'checkout', '-q', 'main');
      writeFileSync(
        users,
        readFileSync(users, 'utf8')
          .replace(
            '"SELECT id, email FROM users WHERE name = \'" + name + "\'"',
            "'SELECT id, email FROM users WHERE name = $1'",
          )
          .replace('await db.query(sql)', 'await db.query(sql, [name])'),
      );
      git(shop, 'commit', '-q', '-am', 'fix sqli');
      await push(shopProject.projectId, shopProject.webhookSecret, shop, 'main');
      expect((await drain()).map((j) => j.status)).toEqual(['SUCCEEDED']);

      // (2) The same finding is FIXED on main and OPEN on develop, in the API and the web UI.
      const findings = (await api(`/v1/projects/${shopProject.projectId}/findings`)).body as Array<{
        findingId: string;
        category: string;
        branches: Record<string, { state: string }>;
      }>;
      const sqli = findings.filter((f) => f.category === 'SQL_INJECTION');
      expect(sqli.map((f) => [f.branches.main?.state, f.branches.develop?.state])).toEqual([
        ['FIXED', 'OPEN'],
        ['OPEN', 'OPEN'],
      ]);
      const [fixedId, openId] = sqli.map((f) => f.findingId) as [string, string];
      const login = await server.app.request('/ui/login', {
        method: 'POST',
        body: new URLSearchParams({ token: admin }),
      });
      const cookie = (login.headers.get('set-cookie') ?? '').split(';')[0] as string;
      const page = await (
        await server.app.request(`/ui/projects/${shopProject.projectId}`, { headers: { cookie } })
      ).text();
      // Branch columns are sorted (develop, main): the row shows open then fixed.
      expect(page.indexOf('<th>develop</th>')).toBeLessThan(page.indexOf('<th>main</th>'));
      const start = page.indexOf(`>${fixedId}<`);
      const row = page.slice(start, page.indexOf('</tr>', start));
      expect(row.indexOf('chip OPEN')).toBeGreaterThan(0);
      expect(row.indexOf('chip FIXED')).toBeGreaterThan(row.indexOf('chip OPEN'));

      // (3) The release gate passes with a fresh scan and fails once the last full scan is older than 72 h.
      expect((await api(`/v1/projects/${shopProject.projectId}/gate?branch=main`)).body.passed).toBe(true);
      const realNow = now;
      now = new Date(realNow.getTime() + 73 * 3_600_000);
      const stale = (await api(`/v1/projects/${shopProject.projectId}/gate?branch=main`)).body;
      expect(stale.passed).toBe(false);
      expect(stale.checks.filter((c: { passed: boolean }) => !c.passed).map((c: { id: string }) => c.id)).toEqual([
        'scan-age',
      ]);
      now = realNow;

      // (1) A new advisory listed in KEV reaches the knowledge base: only "shop" is reassessed, with
      // the dependency scanner alone, and the new finding carries NEW_ADVISORY and KEV.
      expect((await api('/v1/kb/sync', { method: 'POST' })).status).toBe(202);
      const started = Date.now();
      const jobs = await drain();
      const sync = jobs.find((j) => j.kind === 'KB_SYNC');
      expect(sync?.status).toBe('SUCCEEDED');
      expect(sync?.result?.changedAdvisories).toEqual(['GHSA-29mw-wpgm-hmr9']);
      expect(
        ((sync?.result?.reassess ?? []) as Array<{ projectId: string; branch: string }>)
          .map((r) => [r.projectId, r.branch])
          .sort(),
      ).toEqual([
        [shopProject.projectId, 'develop'],
        [shopProject.projectId, 'main'],
      ]);
      const reassess = jobs.filter((j) => j.kind === 'REASSESS');
      expect(reassess.map((j) => [j.status, j.result?.mode, j.result?.tasks])).toEqual([
        ['SUCCEEDED', 'DEPENDENCY_REASSESSMENT', ['osv-scanner']],
        ['SUCCEEDED', 'DEPENDENCY_REASSESSMENT', ['osv-scanner']],
      ]);
      expect(Date.now() - started).toBeLessThan(3_600_000);
      const mainReassess = reassess.find((j) => j.payload.branch === 'main');
      const newId = ((mainReassess?.result?.newFindings ?? []) as string[])[0] as string;
      const detail = (await api(`/v1/projects/${shopProject.projectId}/findings/${newId}`)).body;
      expect(detail.finding).toMatchObject({
        category: 'VULNERABLE_DEPENDENCY',
        title: expect.stringContaining('ReDoS'),
      });
      // Same finding on both branches: NEW where reassessed first, EXISTING on the other.
      const onMain = detail.history.find((h: { branch: string }) => h.branch === 'main');
      expect(onMain).toMatchObject({ reconciliationState: 'NEW', mode: 'DEPENDENCY_REASSESSMENT' });
      expect(onMain.changeCauses).toContain('NEW_ADVISORY');
      expect(onMain.intel).toMatchObject({ cves: ['CVE-2020-28500'], kev: { dateAdded: '2026-10-30' } });
      expect(detail.branches).toMatchObject({
        main: { state: 'OPEN', kev: true },
        develop: { state: 'OPEN', kev: true },
      });
      const notified = events.find((e) => e.trigger === 'reassessment' && e.branch === 'main') as {
        findings: Array<{ findingId: string; kev?: boolean }>;
        signature: string;
      };
      expect(notified.findings).toEqual([expect.objectContaining({ findingId: newId, kev: true })]);
      expect(notified.signature).toMatch(/^sha256=[0-9a-f]{64}$/);

      // SAST state is carried through the dependency-only scan; the KEV finding now blocks the gate.
      const after = (await api(`/v1/projects/${shopProject.projectId}/findings?branch=main`)).body as Array<{
        findingId: string;
        branch: { state: string; carriedThrough?: string };
      }>;
      expect(after.find((f) => f.findingId === openId)?.branch).toMatchObject({
        state: 'OPEN',
        carriedThrough: mainReassess?.result?.scanId,
      });
      expect(after.find((f) => f.findingId === fixedId)?.branch.state).toBe('FIXED');
      const gate = (await api(`/v1/projects/${shopProject.projectId}/gate?branch=main`)).body;
      expect(gate.passed).toBe(false);
      expect(gate.blocking).toEqual([
        expect.objectContaining({ findingId: newId, reasons: [expect.stringContaining('CISA KEV')] }),
      ]);
      expect(
        events.filter(
          (e) => e.project && (e.project as { name: string }).name === 'other' && e.trigger === 'reassessment',
        ),
      ).toEqual([]);
    } finally {
      await server.close();
    }
  }, 600_000);
});
