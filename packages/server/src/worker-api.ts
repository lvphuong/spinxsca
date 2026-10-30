import { join } from 'node:path';
import type { Clock, ScanRepository } from '@spinxsca/core';
import type { SigningKey } from '@spinxsca/kb';
import type { Digest } from '@spinxsca/schemas';
import type { Hono, MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import type { JobEvents } from './events';
import { snapshotBundle } from './kb-signing';
import { type JobEntry, REMOTE_JOB_KINDS, type Registry, type WorkerEntry } from './registry';
import { decode, encode, REPOSITORY_METHODS, WRITE_METHODS } from './rpc';
import type { ProjectStates } from './state';
import { publicProject } from './views';

export interface WorkerApiContext {
  registry: Registry;
  states: ProjectStates;
  clock: Clock;
  events: JobEvents;
  kbDir: string;
  dataDir: string;
  signingKey: SigningKey;
  leaseMs: number;
}

type WorkerEnv = { Variables: { worker: WorkerEntry; job: JobEntry } };
const WRITES: ReadonlySet<string> = new Set(WRITE_METHODS);
const DIGEST = /^sha256:[0-9a-f]{64}$/;

/**
 * Remote worker protocol (docs/architecture/06 section 3.2, ADR-037): HTTPS polling with a worker
 * credential; every job call carries the fencing token of the lease and is limited to the job's
 * project. Workers never get database access.
 */
export function mountWorkerApi(app: Hono, ctx: WorkerApiContext): void {
  const { registry, states, clock } = ctx;

  app.post('/v1/workers/register', async (c) => {
    const body = z
      .strictObject({
        provisioningToken: z.string().min(10),
        name: z.string().min(1).max(100),
        capabilities: z.record(z.string(), z.unknown()).default({}),
      })
      .parse(await c.req.json());
    const registered = registry.registerWorker(body.provisioningToken, body.name, body.capabilities, clock.now());
    if (!registered) throw new HTTPException(401, { message: 'invalid or expired provisioning token' });
    registry.audit(
      `worker:${registered.worker.workerId}`,
      'worker.register',
      registered.worker.workerId,
      { name: body.name, pools: registered.worker.pools },
      clock.now(),
    );
    return c.json({ ...registered.worker, token: registered.token, kbPublicKey: ctx.signingKey.publicKeyPem }, 201);
  });

  const authenticate: MiddlewareHandler<WorkerEnv> = async (c, next) => {
    const header = c.req.header('authorization');
    const worker = header?.startsWith('Bearer ')
      ? registry.authenticateWorker(header.slice(7).trim(), clock.now())
      : undefined;
    if (!worker) throw new HTTPException(401, { message: 'worker authentication required' });
    c.set('worker', worker);
    await next();
  };
  /** The job must be leased by this worker under the presented fencing token. */
  const lease: MiddlewareHandler<WorkerEnv> = async (c, next) => {
    const job = registry.job(c.req.param('jobId') ?? '');
    const fencing = Number(c.req.header('x-spinxsca-fencing'));
    if (!job || job.workerId !== c.get('worker').workerId) throw new HTTPException(404, { message: 'job not found' });
    if (!registry.holdsLease(job.jobId, fencing, clock.now())) throw new HTTPException(409, { message: 'lease lost' });
    c.set('job', job);
    await next();
  };

  const w = app as unknown as Hono<WorkerEnv>;
  w.use('/v1/worker/*', authenticate);

  w.post('/v1/worker/claim', (c) => {
    const worker = c.get('worker');
    const job = registry.claim(clock.now(), ctx.leaseMs, {
      pools: worker.pools,
      kinds: REMOTE_JOB_KINDS,
      workerId: worker.workerId,
    });
    if (!job) return c.body(null, 204);
    const project = job.projectId ? registry.project(job.projectId) : undefined;
    if (!project) {
      registry.fail(job.jobId, 'project no longer exists', clock.now(), job.fencing);
      return c.body(null, 204);
    }
    return c.json({ job, project: publicProject(project), leaseMs: ctx.leaseMs });
  });

  w.post('/v1/worker/jobs/:jobId/heartbeat', lease, (c) => {
    const job = c.get('job');
    const leaseUntil = registry.heartbeat(job.jobId, job.fencing, clock.now(), ctx.leaseMs);
    if (!leaseUntil) throw new HTTPException(409, { message: 'lease lost' });
    return c.json({ leaseUntil });
  });

  w.post('/v1/worker/jobs/:jobId/complete', lease, async (c) => {
    const job = c.get('job');
    const result = z.record(z.string(), z.unknown()).parse(await c.req.json());
    if (!registry.complete(job.jobId, result, clock.now(), job.fencing))
      throw new HTTPException(409, { message: 'lease lost' });
    await ctx.events.completed(job, result);
    return c.json({ status: 'SUCCEEDED' });
  });

  w.post('/v1/worker/jobs/:jobId/fail', lease, async (c) => {
    const job = c.get('job');
    const { error } = z.strictObject({ error: z.string().max(10_000) }).parse(await c.req.json());
    const after = registry.fail(job.jobId, error, clock.now(), job.fencing);
    if (!after) throw new HTTPException(409, { message: 'lease lost' });
    await ctx.events.failed(job, error);
    return c.json({ status: after.status });
  });

  w.post('/v1/worker/jobs/:jobId/repo', lease, async (c) => {
    const job = c.get('job');
    const { method, args } = decode<{ method: string; args: unknown[] }>(await c.req.text());
    if (!REPOSITORY_METHODS.has(method) || !Array.isArray(args))
      throw new HTTPException(400, { message: `method ${method} is not available to workers` });
    const repo = states.get(job.projectId as string).repo as unknown as Record<
      string,
      (...a: unknown[]) => Promise<unknown>
    >;
    const fn = repo[method] as ((...a: unknown[]) => Promise<unknown>) | undefined;
    if (!fn) throw new HTTPException(400, { message: `unknown method ${method}` });
    // Writes are re-checked against the lease right before they happen.
    if (WRITES.has(method) && !registry.holdsLease(job.jobId, job.fencing, clock.now()))
      throw new HTTPException(409, { message: 'lease lost' });
    const result = await fn.apply(repo as unknown as ScanRepository, args);
    return c.body(encode({ result }), 200, { 'content-type': 'application/json' });
  });

  w.put('/v1/worker/jobs/:jobId/artifacts', lease, async (c) => {
    const job = c.get('job');
    const mediaType = c.req.query('mediaType') ?? 'application/octet-stream';
    const bytes = new Uint8Array(await c.req.arrayBuffer());
    return c.json(await states.get(job.projectId as string).artifacts.put(bytes, mediaType), 201);
  });
  w.get('/v1/worker/jobs/:jobId/artifacts/:digest', lease, async (c) => {
    const digest = c.req.param('digest');
    if (!DIGEST.test(digest)) throw new HTTPException(400, { message: 'invalid digest' });
    const artifacts = states.get(c.get('job').projectId as string).artifacts;
    if (!(await artifacts.has(digest as Digest))) {
      if (c.req.query('probe') === '1') return c.json({ exists: false });
      throw new HTTPException(404, { message: 'artifact not found' });
    }
    if (c.req.query('probe') === '1') return c.json({ exists: true });
    return c.body(Uint8Array.from(await artifacts.get(digest as Digest)), 200, {
      'content-type': 'application/octet-stream',
    });
  });

  w.get('/v1/worker/kb/bundle', (c) => {
    const found = snapshotBundle(ctx.kbDir, join(ctx.dataDir, 'kb-bundles'), ctx.signingKey, c.req.query('snapshot'));
    if (!found) throw new HTTPException(404, { message: 'knowledge base snapshot not found' });
    return c.body(Uint8Array.from(found.bundle), 200, {
      'content-type': 'application/octet-stream',
      'x-spinxsca-snapshot': found.snapshotId,
    });
  });
}
