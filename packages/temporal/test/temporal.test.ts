import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { silentLogger } from '@spinxsca/core';
import { importOsvFiles } from '@spinxsca/kb';
import { buildServer } from '@spinxsca/server';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type RunningTemporalWorker, startTemporalWorker, TemporalDispatcher } from '../src/index';

const IMAGE = 'temporalio/temporal:latest';
const dockerReady = (() => {
  try {
    execFileSync('docker', ['image', 'inspect', IMAGE], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
})();

describe.runIf(dockerReady)('Temporal orchestration (docker)', () => {
  let container = '';
  let address = '';
  let dir: string;
  let dispatcher: TemporalDispatcher;
  let temporalWorker: RunningTemporalWorker;
  let server: ReturnType<typeof buildServer>;
  let admin: string;
  let engineCalls = 0;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'spx-temporal-'));
    container = execFileSync('docker', [
      'run',
      '-d',
      '--rm',
      '-p',
      '127.0.0.1::7233',
      IMAGE,
      'server',
      'start-dev',
      '--ip',
      '0.0.0.0',
      '--headless',
    ])
      .toString()
      .trim();
    address = execFileSync('docker', ['port', container, '7233/tcp']).toString().trim();
    for (let i = 0; i < 60; i++) {
      try {
        dispatcher = await TemporalDispatcher.connect({
          address,
          pools: ['default', 'control'],
          retryInitialIntervalSeconds: 1,
        });
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 500));
      }
    }
    server = buildServer({
      dataDir: join(dir, 'data'),
      kbDir: join(dir, 'kb'),
      logger: silentLogger,
      kbSyncIntervalMinutes: 0,
      dispatcher,
      kbSync: async (kb) => ({
        ...importOsvFiles(kb.store, [resolve(__dirname, '../../../evals/fixtures/osv/npm')], {
          authoritativeFor: ['npm'],
        }),
      }),
      engines: () => {
        engineCalls++;
        throw new Error('scanner host unavailable');
      },
    });
    admin = server.registry.createToken('admin', 'admin', new Date()).token;
    temporalWorker = await startTemporalWorker({
      address,
      worker: server.worker,
      logger: silentLogger,
      maxConcurrentActivities: 2,
    });
  }, 120_000);

  afterAll(async () => {
    await temporalWorker?.shutdown();
    await server?.close();
    if (container) execFileSync('docker', ['rm', '-f', container], { stdio: 'pipe' });
    rmSync(dir, { recursive: true, force: true });
  });

  const call = (path: string, method = 'GET', json?: unknown) =>
    server.app.request(path, {
      method,
      headers: { authorization: `Bearer ${admin}`, 'content-type': 'application/json' },
      ...(json ? { body: JSON.stringify(json) } : {}),
    });

  it('runs a job as a workflow and records the outcome in the registry', async () => {
    expect(server.hasLocalPools).toBe(false);
    const job = (await (await call('/v1/kb/sync', 'POST')).json()) as { jobId: string; pool: string };
    expect(job.pool).toBe('control');
    await server.redispatch(); // waits for the (idempotent) workflow start
    const outcome = (await dispatcher.result(job.jobId)) as {
      status: string;
      result: { changed: boolean; snapshotId: string };
    };
    expect(outcome.status).toBe('SUCCEEDED');
    expect(outcome.result.changed).toBe(true);
    expect(server.registry.job(job.jobId)).toMatchObject({
      status: 'SUCCEEDED',
      workerId: `temporal:spinxsca-job-${job.jobId}`,
      attempts: 1,
    });
    // Dispatch is idempotent: the same job maps to the same workflow id.
    await dispatcher.dispatch(server.registry.job(job.jobId) as never);
  }, 120_000);

  it('retries through Temporal within the registry attempt budget, then fails the job for good', async () => {
    const project = (await (
      await call('/v1/projects', 'POST', { name: 'p', source: { kind: 'local', path: dir } })
    ).json()) as { projectId: string };
    const job = (await (await call(`/v1/projects/${project.projectId}/scans`, 'POST', { branch: 'main' })).json()) as {
      jobId: string;
    };
    await server.redispatch();
    await expect(dispatcher.result(job.jobId)).rejects.toThrow();
    expect(server.registry.job(job.jobId)).toMatchObject({
      status: 'FAILED',
      attempts: 3,
      error: 'scanner host unavailable',
    });
    expect(engineCalls).toBe(3);
  }, 120_000);
});
