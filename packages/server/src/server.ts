import { serve } from '@hono/node-server';
import { type Clock, DEFAULT_GATE_POLICY, type Logger, type ReleaseGatePolicy, systemClock } from '@spinxsca/core';
import { createApp } from './app';
import { JobEvents } from './events';
import type { EngineFactory } from './execute';
import { loadSigningKey } from './kb-signing';
import { defaultKbSync } from './kb-sync';
import { Notifier } from './notify';
import { CONTROL_POOL, type JobEntry, Registry } from './registry';
import { ProjectStates } from './state';
import { DEFAULT_LEASE_MS, type KbSyncFn, Worker } from './worker';
import { ProjectWorkspace } from './workspace';

/** External orchestrator (ADR-038, Temporal) that runs the jobs of some pools instead of the polling loop. */
export interface JobDispatcher {
  readonly pools: readonly string[];
  /** Must be idempotent per job id: called again for jobs still queued after a restart. */
  dispatch(job: JobEntry): Promise<void>;
  close?(): Promise<void>;
}

export interface ServerOptions {
  dataDir: string;
  kbDir: string;
  engines: EngineFactory;
  logger: Logger;
  host?: string;
  port?: number;
  clock?: Clock;
  gatePolicy?: ReleaseGatePolicy;
  kbSync?: KbSyncFn;
  /** Minutes between scheduled knowledge base refreshes; 0 disables the schedule. */
  kbSyncIntervalMinutes?: number;
  notifyUrls?: readonly string[];
  notifySecret?: string;
  /** Run scan jobs in this process (default true). Knowledge base refreshes always run here. */
  worker?: boolean;
  /** Worker pools served in-process (default: ["default"]). Other pools need remote workers. */
  pools?: readonly string[];
  leaseMs?: number;
  pollMs?: number;
  publicUrl?: string;
  secureCookies?: boolean;
  /** PostgreSQL for project state (one schema per project); default is a SQLite file per project. */
  databaseUrl?: string;
  dispatcher?: JobDispatcher;
}

export interface RunningServer {
  url: string;
  registry: Registry;
  worker: Worker;
  close(): Promise<void>;
}

/** Builds the service without listening (tests and embedding). */
export function buildServer(options: ServerOptions) {
  const clock = options.clock ?? systemClock;
  const leaseMs = options.leaseMs ?? DEFAULT_LEASE_MS;
  const registry = Registry.open(options.dataDir);
  const workspace = new ProjectWorkspace(options.dataDir);
  const states = new ProjectStates(workspace, options.databaseUrl ? { databaseUrl: options.databaseUrl } : {});
  const notifier = new Notifier({
    urls: options.notifyUrls ?? [],
    ...(options.notifySecret ? { secret: options.notifySecret } : {}),
    logger: options.logger,
  });
  const events = new JobEvents({
    registry,
    states,
    notifier,
    clock,
    ...(options.publicUrl ? { publicUrl: options.publicUrl } : {}),
  });
  const signingKey = loadSigningKey(options.dataDir);
  const worker = new Worker({
    registry,
    workspace,
    states,
    engines: options.engines,
    kbDir: options.kbDir,
    kbSync: options.kbSync ?? defaultKbSync(),
    events,
    clock,
    logger: options.logger,
    leaseMs,
    pools: localPools(options),
  });
  const dispatcher = options.dispatcher;
  if (dispatcher) {
    registry.onEnqueued = (job) => {
      if (dispatcher.pools.includes(job.pool)) {
        dispatcher
          .dispatch(job)
          .catch((err) => options.logger.warn(`dispatch ${job.jobId}: ${(err as Error).message}`));
      }
    };
  }
  /** Re-dispatches queued jobs (orchestrator was unreachable, or the server restarted); idempotent per job. */
  const redispatch = async () => {
    if (!dispatcher) return;
    for (const job of registry.jobs({ status: 'QUEUED', limit: 500 })) {
      if (dispatcher.pools.includes(job.pool))
        await dispatcher
          .dispatch(job)
          .catch((err) => options.logger.warn(`dispatch ${job.jobId}: ${(err as Error).message}`));
    }
  };
  const app = createApp({
    registry,
    states,
    clock,
    gatePolicy: options.gatePolicy ?? DEFAULT_GATE_POLICY,
    kbDir: options.kbDir,
    ...(options.secureCookies ? { secureCookies: true } : {}),
    workerApi: { registry, states, clock, events, kbDir: options.kbDir, dataDir: options.dataDir, signingKey, leaseMs },
  });
  /** Enqueues the periodic knowledge base refresh once per interval (idempotent per time bucket). */
  const scheduleKbSync = () => {
    const minutes = options.kbSyncIntervalMinutes ?? 30;
    if (minutes <= 0) return undefined;
    const bucket = Math.floor(clock.now().getTime() / (minutes * 60_000));
    return registry.enqueue(
      { kind: 'KB_SYNC', payload: { trigger: 'schedule' }, idempotencyKey: `kb-sync:${minutes}:${bucket}` },
      clock.now(),
    ).job;
  };
  const close = async () => {
    await worker.stop();
    await dispatcher?.close?.();
    await states.close();
    registry.close();
  };
  return {
    app,
    registry,
    states,
    worker,
    events,
    signingKey,
    scheduleKbSync,
    redispatch,
    hasLocalPools: localPools(options).length > 0,
    close,
  };
}

export async function startServer(options: ServerOptions): Promise<RunningServer> {
  const built = buildServer(options);
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 8080;
  const server = await new Promise<ReturnType<typeof serve>>((resolve) => {
    const s = serve({ fetch: built.app.fetch, hostname: host, port }, () => resolve(s));
  });
  const address = server.address();
  const actualPort = typeof address === 'object' && address ? address.port : port;
  if (built.hasLocalPools) built.worker.start(options.pollMs ?? 1000);
  built.scheduleKbSync();
  await built.redispatch();
  const scheduler = setInterval(() => {
    built.scheduleKbSync();
    void built.redispatch();
  }, 60_000);
  return {
    url: `http://${host.includes(':') ? `[${host}]` : host}:${actualPort}`,
    registry: built.registry,
    worker: built.worker,
    close: async () => {
      clearInterval(scheduler);
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await built.close();
    },
  };
}

/** Pools the polling loop serves: the in-process scan pools plus the control pool, minus dispatched ones. */
function localPools(options: ServerOptions): string[] {
  const pools = [...(options.worker === false ? [] : (options.pools ?? ['default'])), CONTROL_POOL];
  return [...new Set(pools)].filter((p) => !options.dispatcher?.pools.includes(p));
}
