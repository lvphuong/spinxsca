import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { silentLogger } from '@spinxsca/core';
import { importBundle, importOsvFiles, KbStore } from '@spinxsca/kb';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildServer, decode, encode, RemoteWorker, registerWorker } from '../src/index';

let dir: string;
let now = new Date('2026-10-30T00:00:00Z');
const clock = { now: () => now };
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'spx-wp-'));
  now = new Date('2026-10-30T00:00:00Z');
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function setup() {
  const server = buildServer({
    dataDir: join(dir, 'data'),
    kbDir: join(dir, 'kb'),
    logger: silentLogger,
    clock,
    leaseMs: 60_000,
    engines: () => {
      throw new Error('no scans here');
    },
  });
  const admin = server.registry.createToken('admin', 'admin', now).token;
  const fetchApp = ((url: string | URL, init?: RequestInit) => server.app.request(String(url), init)) as typeof fetch;
  const call = (
    path: string,
    init: { method?: string; token?: string; body?: string; fencing?: number; json?: unknown } = {},
  ) =>
    server.app.request(path, {
      method: init.method ?? 'GET',
      headers: {
        ...(init.token ? { authorization: `Bearer ${init.token}` } : {}),
        ...(init.fencing !== undefined ? { 'x-spinxsca-fencing': String(init.fencing) } : {}),
        'content-type': 'application/json',
      },
      ...(init.json !== undefined
        ? { body: JSON.stringify(init.json) }
        : init.body !== undefined
          ? { body: init.body }
          : {}),
    });
  const provision = async (pools: string[]) =>
    (
      (await (await call('/v1/workers/provision', { method: 'POST', token: admin, json: { pools } })).json()) as {
        provisioningToken: string;
      }
    ).provisioningToken;
  return { server, admin, call, fetchApp, provision };
}

describe('remote worker protocol', () => {
  it('provisions single-use registrations and routes jobs by pool', async () => {
    const { server, admin, call, fetchApp, provision } = setup();
    try {
      const token = await provision(['onprem']);
      const worker = await registerWorker({
        server: 'http://cp',
        provisioningToken: token,
        name: 'w1',
        fetch: fetchApp,
      });
      expect(worker.token.startsWith('spxw_')).toBe(true);
      expect(worker.kbPublicKey).toContain('BEGIN PUBLIC KEY');
      await expect(
        registerWorker({ server: 'http://cp', provisioningToken: token, name: 'again', fetch: fetchApp }),
      ).rejects.toThrow('HTTP 401');
      // Worker credentials are not user tokens and vice versa.
      expect((await call('/v1/projects', { token: worker.token })).status).toBe(401);
      expect((await call('/v1/worker/claim', { method: 'POST', token: admin })).status).toBe(401);

      const created = (await (
        await call('/v1/projects', {
          method: 'POST',
          token: admin,
          json: { name: 'p1', source: { kind: 'git', url: 'https://x/p1.git' }, workerPool: 'onprem' },
        })
      ).json()) as { projectId: string; workerPool: string };
      expect(created.workerPool).toBe('onprem');
      server.registry.enqueue({ kind: 'KB_SYNC', payload: {} }, now);
      server.registry.enqueue({ kind: 'SCAN', projectId: created.projectId, payload: { branch: 'main' } }, now);
      // The in-process worker serves "default" (and the control pool): it takes KB_SYNC, never the on-prem scan.
      expect(server.registry.claim(now, 60_000, { pools: ['default'], kinds: ['SCAN', 'REASSESS'] })).toBeUndefined();
      const claim = await call('/v1/worker/claim', { method: 'POST', token: worker.token });
      const body = (await claim.json()) as {
        job: { jobId: string; kind: string; fencing: number; pool: string };
        project: Record<string, unknown>;
      };
      expect(body.job).toMatchObject({ kind: 'SCAN', fencing: 1, pool: 'onprem' });
      expect(body.project).not.toHaveProperty('webhookSecret');
      expect((await call('/v1/worker/claim', { method: 'POST', token: worker.token })).status).toBe(204);
      const workers = (await (await call('/v1/workers', { token: admin })).json()) as Array<{
        name: string;
        capabilities: { cpus: number };
      }>;
      expect(workers[0]?.name).toBe('w1');
      expect(workers[0]?.capabilities.cpus).toBeGreaterThan(0);
    } finally {
      await server.close();
    }
  });

  it('fences writes: a worker that lost its lease can no longer write, heartbeat or complete', async () => {
    const { server, admin, call, fetchApp, provision } = setup();
    try {
      const a = await registerWorker({
        server: 'http://cp',
        provisioningToken: await provision(['default']),
        name: 'a',
        fetch: fetchApp,
      });
      const b = await registerWorker({
        server: 'http://cp',
        provisioningToken: await provision(['default']),
        name: 'b',
        fetch: fetchApp,
      });
      const project = (await (
        await call('/v1/projects', {
          method: 'POST',
          token: admin,
          json: { name: 'p', source: { kind: 'git', url: 'https://x/p.git' } },
        })
      ).json()) as {
        projectId: string;
      };
      server.registry.enqueue({ kind: 'SCAN', projectId: project.projectId, payload: { branch: 'main' } }, now);
      const first = (
        (await (await call('/v1/worker/claim', { method: 'POST', token: a.token })).json()) as {
          job: { jobId: string; fencing: number };
        }
      ).job;
      const repo = (token: string, fencing: number, method: string, args: unknown[]) =>
        call(`/v1/worker/jobs/${first.jobId}/repo`, { method: 'POST', token, fencing, body: encode({ method, args }) });

      const ensured = await repo(a.token, first.fencing, 'ensureProject', [{ name: 'p', rootPath: '/src' }]);
      expect(ensured.status).toBe(200);
      const engineProject = decode<{ result: { project: { projectId: string } } }>(await ensured.text()).result.project
        .projectId;
      const index = decode<{ result: Map<string, string> }>(
        await (await repo(a.token, first.fencing, 'fingerprintIndex', [engineProject])).text(),
      ).result;
      expect(index).toBeInstanceOf(Map);
      expect((await repo(a.token, first.fencing, 'saveDisposition', [{}])).status).toBe(400);
      expect((await repo(a.token, first.fencing + 1, 'listScans', [engineProject])).status).toBe(409);
      expect((await repo(b.token, first.fencing, 'listScans', [engineProject])).status).toBe(404);

      const put = await call(`/v1/worker/jobs/${first.jobId}/artifacts?mediaType=text/plain`, {
        method: 'PUT',
        token: a.token,
        fencing: first.fencing,
        body: 'hello',
      });
      const ref = (await put.json()) as { digest: string };
      expect(
        await (
          await call(`/v1/worker/jobs/${first.jobId}/artifacts/${ref.digest}`, {
            token: a.token,
            fencing: first.fencing,
          })
        ).text(),
      ).toBe('hello');
      expect(
        await (
          await call(`/v1/worker/jobs/${first.jobId}/artifacts/sha256:${'0'.repeat(64)}?probe=1`, {
            token: a.token,
            fencing: first.fencing,
          })
        ).json(),
      ).toEqual({ exists: false });

      // Worker A stalls past its lease; B claims the same job with a new fencing token.
      now = new Date(now.getTime() + 61_000);
      const second = (
        (await (await call('/v1/worker/claim', { method: 'POST', token: b.token })).json()) as {
          job: { jobId: string; fencing: number };
        }
      ).job;
      expect(second).toMatchObject({ jobId: first.jobId, fencing: 2 });
      expect((await repo(a.token, first.fencing, 'createScan', [{}])).status).toBe(404);
      expect(
        (
          await call(`/v1/worker/jobs/${first.jobId}/heartbeat`, {
            method: 'POST',
            token: a.token,
            fencing: first.fencing,
          })
        ).status,
      ).toBe(404);
      const done = await call(`/v1/worker/jobs/${first.jobId}/complete`, {
        method: 'POST',
        token: b.token,
        fencing: second.fencing,
        json: { ok: true },
      });
      expect(done.status).toBe(200);
      expect(server.registry.job(first.jobId)).toMatchObject({ status: 'SUCCEEDED', result: { ok: true } });
      expect(
        (
          await call(`/v1/worker/jobs/${first.jobId}/complete`, {
            method: 'POST',
            token: b.token,
            fencing: second.fencing,
            json: {},
          })
        ).status,
      ).toBe(409);
      // Revoked workers are locked out.
      await call(`/v1/workers/${server.registry.workers()[0]?.workerId}`, { method: 'DELETE', token: admin });
      expect((await call('/v1/worker/claim', { method: 'POST', token: a.token })).status).toBe(401);
    } finally {
      await server.close();
    }
  });

  it('ships the control plane knowledge base as a signed bundle', async () => {
    const { server, fetchApp, provision } = setup();
    try {
      const config = await registerWorker({
        server: 'http://cp',
        provisioningToken: await provision(['default']),
        name: 'w',
        fetch: fetchApp,
      });
      const worker = new RemoteWorker({
        config,
        dataDir: join(dir, 'worker'),
        logger: silentLogger,
        fetch: fetchApp,
        engines: () => {
          throw new Error('unused');
        },
      });
      await worker.syncKnowledgeBase(undefined); // nothing to sync yet
      const store = KbStore.open(join(dir, 'kb'));
      importOsvFiles(store, [resolve(__dirname, '../../../evals/fixtures/osv/npm')], { authoritativeFor: ['npm'] });
      const snapshot = store.createSnapshot();
      store.close();
      await worker.syncKnowledgeBase(undefined);
      const replica = KbStore.open(worker.kbDir);
      expect(replica.latestSnapshot()?.snapshotId).toBe(snapshot.snapshotId);
      replica.close();
      await worker.syncKnowledgeBase(snapshot.snapshotId); // already present: no download
      const res = await fetchApp('http://cp/v1/worker/kb/bundle', {
        headers: { authorization: `Bearer ${config.token}` },
      });
      const other = KbStore.open(join(dir, 'other'));
      const bytes = new Uint8Array(await res.arrayBuffer());
      expect(() => importBundle(other, bytes, [])).toThrow('untrusted key');
      other.close();
    } finally {
      await server.close();
    }
  });
});
