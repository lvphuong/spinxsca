import { existsSync, mkdirSync } from 'node:fs';
import { arch, cpus, freemem, hostname, platform, totalmem } from 'node:os';
import { join } from 'node:path';
import type { ArtifactStore, Logger, ScanRepository } from '@spinxsca/core';
import { importBundle, KbStore } from '@spinxsca/kb';
import type { ArtifactRef, Digest } from '@spinxsca/schemas';
import { type EngineFactory, executeJob } from './execute';
import type { JobEntry, ProjectEntry } from './registry';
import { decode, encode, REPOSITORY_METHODS } from './rpc';
import { ProjectWorkspace } from './workspace';

export interface RemoteWorkerConfig {
  server: string;
  workerId: string;
  token: string;
  /** Control plane key that signs knowledge base bundles (pinned at registration). */
  kbPublicKey: string;
}

export interface RemoteWorkerOptions {
  config: RemoteWorkerConfig;
  /** Local directory: checkouts, scratch, code index cache, and the bundle-fed knowledge base. */
  dataDir: string;
  engines: EngineFactory;
  logger: Logger;
  fetch?: typeof fetch;
}

class LeaseLost extends Error {
  constructor() {
    super('lease lost');
  }
}

/** Capabilities a worker reports at registration (docs/architecture/06 section 3.2). */
export function workerCapabilities(): Record<string, unknown> {
  return {
    os: platform(),
    arch: arch(),
    cpus: cpus().length,
    memoryMb: Math.round(totalmem() / 1048576),
    freeMemoryMb: Math.round(freemem() / 1048576),
    host: hostname(),
  };
}

/** Exchanges a provisioning token for a worker credential and the bundle-signing key. */
export async function registerWorker(input: {
  server: string;
  provisioningToken: string;
  name: string;
  fetch?: typeof fetch;
}): Promise<RemoteWorkerConfig> {
  const http = input.fetch ?? fetch;
  const res = await http(`${input.server.replace(/\/+$/, '')}/v1/workers/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      provisioningToken: input.provisioningToken,
      name: input.name,
      capabilities: workerCapabilities(),
    }),
  });
  if (!res.ok) throw new Error(`registration failed: HTTP ${res.status} ${await res.text()}`);
  const body = (await res.json()) as { workerId: string; token: string; kbPublicKey: string };
  return {
    server: input.server.replace(/\/+$/, ''),
    workerId: body.workerId,
    token: body.token,
    kbPublicKey: body.kbPublicKey,
  };
}

/**
 * Remote worker (ADR-037): polls the control plane, runs leased SCAN/REASSESS jobs next to the source
 * (on-prem, CI runner, developer machine), and writes results through the control plane under the
 * lease's fencing token. It needs no database and no inbound connectivity.
 */
export class RemoteWorker {
  private readonly http: typeof fetch;
  private readonly base: string;
  private stopped = false;
  private running: Promise<unknown> | undefined;

  constructor(private readonly o: RemoteWorkerOptions) {
    this.http = o.fetch ?? fetch;
    this.base = o.config.server;
    mkdirSync(o.dataDir, { recursive: true });
  }

  async start(pollMs = 5000): Promise<void> {
    this.stopped = false;
    while (!this.stopped) {
      try {
        this.running = this.runOnce();
        const ran = await this.running;
        if (!ran) await new Promise((r) => setTimeout(r, pollMs));
      } catch (err) {
        this.o.logger.error(`worker: ${(err as Error).message}`);
        await new Promise((r) => setTimeout(r, pollMs));
      }
    }
  }

  async stop(): Promise<void> {
    this.stopped = true;
    await this.running?.catch(() => {});
  }

  /** Claims and runs one job; false when nothing was available. */
  async runOnce(): Promise<JobEntry | false> {
    const claim = await this.request('POST', '/v1/worker/claim');
    if (claim.status === 204) return false;
    if (!claim.ok) throw new Error(`claim failed: HTTP ${claim.status}`);
    const { job, project, leaseMs } = (await claim.json()) as { job: JobEntry; project: ProjectEntry; leaseMs: number };
    this.o.logger.info(`job ${job.jobId} ${job.kind} ${project.name} (fencing ${job.fencing})`);
    const abort = new AbortController();
    const renew = setInterval(
      async () => {
        const res = await this.request('POST', `/v1/worker/jobs/${job.jobId}/heartbeat`, undefined, job.fencing).catch(
          () => undefined,
        );
        if (res?.status === 409) abort.abort(new LeaseLost());
      },
      Math.max(1000, Math.floor(leaseMs / 3)),
    );
    try {
      const repo = this.repository(job);
      const result = await executeJob(
        job,
        { ...project, webhookSecret: '' },
        {
          workspace: new ProjectWorkspace(join(this.o.dataDir, 'workspace')),
          engine: ({ projectId, sourceDir }) =>
            this.o.engines({
              sourceDir,
              stateDir: join(this.o.dataDir, 'state', projectId),
              repo,
              artifacts: this.artifacts(job),
            }),
          repository: () => repo,
          prepareKnowledgeBase: (snapshotId) => this.syncKnowledgeBase(snapshotId),
          signal: abort.signal,
        },
      );
      const done = await this.request(
        'POST',
        `/v1/worker/jobs/${job.jobId}/complete`,
        JSON.stringify(result),
        job.fencing,
      );
      if (done.status === 409) throw new LeaseLost();
      if (!done.ok) throw new Error(`complete failed: HTTP ${done.status}`);
    } catch (err) {
      if (err instanceof LeaseLost || abort.signal.aborted) {
        this.o.logger.warn(`job ${job.jobId}: lease lost; result discarded`);
      } else {
        const message = (err as Error).message;
        this.o.logger.error(`job ${job.jobId} failed: ${message}`);
        await this.request(
          'POST',
          `/v1/worker/jobs/${job.jobId}/fail`,
          JSON.stringify({ error: message }),
          job.fencing,
        ).catch(() => undefined);
      }
    } finally {
      clearInterval(renew);
    }
    return job;
  }

  /** Imports the control plane's snapshot (latest, or the pinned one) as a verified bundle. */
  async syncKnowledgeBase(snapshotId: string | undefined): Promise<void> {
    const dir = join(this.o.dataDir, 'kb');
    const store = KbStore.open(dir);
    try {
      if (snapshotId && store.snapshot(snapshotId)) return;
      const res = await this.request(
        'GET',
        `/v1/worker/kb/bundle${snapshotId ? `?snapshot=${encodeURIComponent(snapshotId)}` : ''}`,
      );
      if (res.status === 404 && !snapshotId) return; // control plane has no knowledge base yet
      if (!res.ok) throw new Error(`knowledge base bundle: HTTP ${res.status}`);
      const latest = res.headers.get('x-spinxsca-snapshot');
      if (latest && store.snapshot(latest)) return;
      const imported = importBundle(store, new Uint8Array(await res.arrayBuffer()), [this.o.config.kbPublicKey]);
      this.o.logger.info(
        `knowledge base snapshot ${imported.snapshot.snapshotId} imported (${imported.header.records} advisories)`,
      );
    } finally {
      store.close();
    }
  }

  /** Knowledge base directory the engines must use. */
  get kbDir(): string {
    return join(this.o.dataDir, 'kb');
  }

  private repository(job: JobEntry): ScanRepository {
    const call = async (method: string, args: unknown[]) => {
      const res = await this.request(
        'POST',
        `/v1/worker/jobs/${job.jobId}/repo`,
        encode({ method, args }),
        job.fencing,
      );
      if (res.status === 409) throw new LeaseLost();
      if (!res.ok) throw new Error(`repository ${method}: HTTP ${res.status} ${await res.text()}`);
      return decode<{ result: unknown }>(await res.text()).result;
    };
    return new Proxy({} as ScanRepository, {
      get: (_target, prop) => {
        if (typeof prop !== 'string' || !REPOSITORY_METHODS.has(prop)) return undefined;
        return (...args: unknown[]) => call(prop, args);
      },
    });
  }

  private artifacts(job: JobEntry): ArtifactStore {
    const path = (digest: Digest) => `/v1/worker/jobs/${job.jobId}/artifacts/${digest}`;
    return {
      put: async (data, mediaType) => {
        const res = await this.request(
          'PUT',
          `/v1/worker/jobs/${job.jobId}/artifacts?mediaType=${encodeURIComponent(mediaType)}`,
          typeof data === 'string' ? data : Buffer.from(data),
          job.fencing,
        );
        if (res.status === 409) throw new LeaseLost();
        if (!res.ok) throw new Error(`artifact upload: HTTP ${res.status}`);
        return (await res.json()) as ArtifactRef;
      },
      get: async (digest) => {
        const res = await this.request('GET', path(digest), undefined, job.fencing);
        if (!res.ok) throw new Error(`artifact ${digest}: HTTP ${res.status}`);
        return new Uint8Array(await res.arrayBuffer());
      },
      getText: async (digest) => {
        const res = await this.request('GET', path(digest), undefined, job.fencing);
        if (!res.ok) throw new Error(`artifact ${digest}: HTTP ${res.status}`);
        return res.text();
      },
      has: async (digest) => {
        const res = await this.request('GET', `${path(digest)}?probe=1`, undefined, job.fencing);
        return res.ok && ((await res.json()) as { exists: boolean }).exists;
      },
    };
  }

  private request(method: string, path: string, body?: string | Buffer, fencing?: number): Promise<Response> {
    return this.http(`${this.base}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${this.o.config.token}`,
        ...(fencing !== undefined ? { 'x-spinxsca-fencing': String(fencing) } : {}),
        ...(body !== undefined
          ? { 'content-type': typeof body === 'string' ? 'application/json' : 'application/octet-stream' }
          : {}),
      },
      ...(body !== undefined ? { body: typeof body === 'string' ? body : new Uint8Array(body) } : {}),
    });
  }
}

export function workerConfigExists(dataDir: string): boolean {
  return existsSync(join(dataDir, 'worker.json'));
}
