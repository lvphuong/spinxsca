import { type Clock, dependencyInventory, type InventoryPackage, type Logger, scansByBranch } from '@spinxsca/core';
import { LocalKnowledgeBase, normalizePackageName } from '@spinxsca/kb';
import type { JobEvents } from './events';
import { type EngineFactory, executeJob } from './execute';
import { CONTROL_POOL, type JobEntry, type JobKind, LOCAL_WORKER, type Registry } from './registry';
import type { ProjectStates } from './state';
import type { ProjectWorkspace } from './workspace';

export type { EngineFactory, ScanEngine, ScanPayload } from './execute';

export interface ProjectInventory {
  projectId: string;
  branch: string;
  scanId: string;
  packages: InventoryPackage[];
}

/** Refreshes the knowledge base; the default syncs OSV for every project's packages plus KEV and EPSS. */
export type KbSyncFn = (
  kb: LocalKnowledgeBase,
  ctx: { inventories: ProjectInventory[]; logger: Logger },
) => Promise<Record<string, unknown>>;

export interface WorkerOptions {
  registry: Registry;
  workspace: ProjectWorkspace;
  states: ProjectStates;
  engines: EngineFactory;
  kbDir: string;
  kbSync: KbSyncFn;
  events: JobEvents;
  clock: Clock;
  logger: Logger;
  leaseMs?: number;
  /** Pools served by the polling loop (default: default and control). */
  pools?: readonly string[];
}

export const DEFAULT_LEASE_MS = 10 * 60_000;

/**
 * In-process job runner (ADR-034, ADR-037). Jobs are leased with a fencing token and the lease is
 * renewed while the job runs; if it is lost (process paused past the lease, job reclaimed by another
 * worker), the job is aborted and its outcome discarded.
 */
export class Worker {
  private timer: NodeJS.Timeout | undefined;
  private running: Promise<unknown> | undefined;
  private stopped = false;

  constructor(private readonly o: WorkerOptions) {}

  start(pollMs = 1000): void {
    this.stopped = false;
    const tick = async () => {
      if (this.stopped) return;
      try {
        this.running = this.runOnce();
        await this.running;
      } catch (err) {
        this.o.logger.error(`worker: ${(err as Error).message}`);
      } finally {
        this.running = undefined;
        if (!this.stopped) this.timer = setTimeout(tick, pollMs);
      }
    };
    this.timer = setTimeout(tick, 0);
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    await this.running?.catch(() => {});
  }

  /** Claims and runs one job; returns it, or undefined when nothing is ready. */
  async runOnce(): Promise<JobEntry | undefined> {
    const kinds: JobKind[] = ['SCAN', 'REASSESS', 'KB_SYNC'];
    const pools = this.o.pools ?? ['default', CONTROL_POOL];
    if (pools.length === 0) return undefined;
    const job = this.o.registry.claim(this.o.clock.now(), this.leaseMs, { pools, kinds, workerId: LOCAL_WORKER });
    return job ? this.runClaimed(job) : undefined;
  }

  /**
   * Runs one specific job on behalf of an external orchestrator (Temporal activity). A job that is
   * already finished is returned unchanged, so a retried activity after success stays successful.
   */
  async runJob(jobId: string, signal?: AbortSignal, workerId = 'temporal'): Promise<JobEntry | undefined> {
    const job = this.o.registry.claimById(jobId, this.o.clock.now(), this.leaseMs, workerId);
    return job ? this.runClaimed(job, signal) : this.o.registry.job(jobId);
  }

  private get leaseMs(): number {
    return this.o.leaseMs ?? DEFAULT_LEASE_MS;
  }

  private async runClaimed(job: JobEntry, signal?: AbortSignal): Promise<JobEntry | undefined> {
    const { registry, clock } = this.o;
    this.o.logger.info(
      `job ${job.jobId} ${job.kind}${job.projectId ? ` ${job.projectId}` : ''} (attempt ${job.attempts})`,
    );
    const abort = new AbortController();
    const onCancel = () => abort.abort(signal?.reason ?? new Error('cancelled'));
    signal?.addEventListener('abort', onCancel, { once: true });
    const renew = setInterval(
      () => {
        if (!registry.heartbeat(job.jobId, job.fencing, clock.now(), this.leaseMs))
          abort.abort(new Error('lease lost'));
      },
      Math.max(1000, Math.floor(this.leaseMs / 3)),
    );
    try {
      const result = job.kind === 'KB_SYNC' ? await this.kbSync() : await this.execute(job, abort.signal);
      if (registry.complete(job.jobId, result, clock.now(), job.fencing)) await this.o.events.completed(job, result);
      else this.o.logger.warn(`job ${job.jobId}: lease lost before completion; result discarded`);
    } catch (err) {
      const message = (err as Error).message;
      const after = registry.fail(job.jobId, message, clock.now(), job.fencing);
      this.o.logger.error(
        `job ${job.jobId} failed (${after?.status === 'QUEUED' ? 'will retry' : 'giving up'}): ${message}`,
      );
      if (after) await this.o.events.failed(job, message);
    } finally {
      clearInterval(renew);
      signal?.removeEventListener('abort', onCancel);
    }
    return registry.job(job.jobId);
  }

  private async execute(job: JobEntry, signal: AbortSignal): Promise<Record<string, unknown>> {
    const project = job.projectId ? this.o.registry.project(job.projectId) : undefined;
    if (!project) throw new Error(`project ${job.projectId} not found`);
    return executeJob(job, project, {
      workspace: this.o.workspace,
      engine: ({ projectId, sourceDir }) => {
        const state = this.o.states.get(projectId);
        return this.o.engines({
          sourceDir,
          stateDir: this.o.workspace.paths(projectId).state,
          repo: state.repo,
          artifacts: state.artifacts,
        });
      },
      repository: (projectId) => this.o.states.get(projectId).repo,
      signal,
    });
  }

  /**
   * Refreshes the knowledge base, and when the snapshot changed, enqueues a dependency reassessment
   * for every project branch whose inventory contains a package named by a new or changed advisory.
   */
  private async kbSync(): Promise<Record<string, unknown>> {
    const kb = LocalKnowledgeBase.open(this.o.kbDir);
    try {
      const inventories = await this.inventories();
      const previous = kb.store.latestSnapshot();
      const sync = await this.o.kbSync(kb, { inventories, logger: this.o.logger });
      const next = kb.store.createSnapshot();
      if (previous && previous.snapshotId === next.snapshotId)
        return { snapshotId: next.snapshotId, changed: false, sync };
      const changed = await kb.changedPackages(previous?.snapshotId, next.snapshotId);
      const keys = new Map<string, Set<string>>();
      for (const c of changed) {
        const key = `${c.ecosystem}\u0000${normalizePackageName(c.ecosystem, c.name)}`;
        keys.set(key, (keys.get(key) ?? new Set()).add(c.advisory));
      }
      const reassess: Array<{ projectId: string; branch: string; jobId: string; advisories: string[] }> = [];
      for (const inv of inventories) {
        const advisories = new Set<string>();
        for (const pkg of inv.packages) {
          for (const a of keys.get(`${pkg.ecosystem}\u0000${normalizePackageName(pkg.ecosystem, pkg.name)}`) ?? [])
            advisories.add(a);
        }
        if (advisories.size === 0) continue;
        const { job } = this.o.registry.enqueue(
          {
            kind: 'REASSESS',
            projectId: inv.projectId,
            payload: {
              branch: inv.branch,
              kbSnapshotId: next.snapshotId,
              advisories: [...advisories].sort(),
              trigger: 'reassessment',
            },
            idempotencyKey: `reassess:${inv.projectId}:${inv.branch}:${next.snapshotId}`,
          },
          this.o.clock.now(),
        );
        reassess.push({
          projectId: inv.projectId,
          branch: inv.branch,
          jobId: job.jobId,
          advisories: [...advisories].sort(),
        });
      }
      return {
        snapshotId: next.snapshotId,
        previous: previous?.snapshotId ?? null,
        changed: true,
        changedAdvisories: [...new Set(changed.map((c) => c.advisory))].sort(),
        reassess,
        sync,
      };
    } finally {
      kb.close();
    }
  }

  /** Dependency inventory of the latest scan of every branch of every project. */
  async inventories(): Promise<ProjectInventory[]> {
    const out: ProjectInventory[] = [];
    for (const project of this.o.registry.projects()) {
      if (!this.o.states.exists(project.projectId)) continue;
      const state = this.o.states.get(project.projectId);
      const engineProject = await state.engineProjectId();
      if (!engineProject) continue;
      for (const [branch, scans] of await scansByBranch(state.repo, engineProject)) {
        for (const scan of scans) {
          const packages = await dependencyInventory(state.repo, state.artifacts, scan.scanId);
          if (!packages) continue;
          out.push({ projectId: project.projectId, branch, scanId: scan.scanId, packages });
          break;
        }
      }
    }
    return out;
  }
}
