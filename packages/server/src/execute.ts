import { type ArtifactStore, runScan, type ScanDeps, type ScanRepository, scansByBranch } from '@spinxsca/core';
import type { ScanMode } from '@spinxsca/schemas';
import type { NotificationEvent } from './notify';
import type { JobEntry, ProjectEntry } from './registry';
import type { ProjectWorkspace } from './workspace';

/** Scan engine for one source directory (built by the CLI runtime). */
export interface ScanEngine {
  deps: ScanDeps;
  close(): void;
}

/**
 * Builds an engine. `stateDir` is a local directory for scratch files and caches; when `repo` and
 * `artifacts` are given (remote workers) they replace the local state database and artifact store.
 */
export type EngineFactory = (input: {
  sourceDir: string;
  stateDir: string;
  repo?: ScanRepository;
  artifacts?: ArtifactStore;
}) => ScanEngine;

export interface ScanPayload {
  branch: string;
  commit?: string;
  mode?: 'FULL' | 'INCREMENTAL';
  diffBase?: string;
  /** Extra refs to fetch before resolving (pull/merge request heads). */
  fetchRefs?: Array<{ remote: string; local: string }>;
  ref?: string;
  trigger?: NotificationEvent['trigger'];
}

/** Where a job runs: checkouts on this machine, and the project state (local files or the control plane). */
export interface JobRuntime {
  workspace: ProjectWorkspace;
  engine(input: { projectId: string; sourceDir: string }): ScanEngine;
  repository(projectId: string): ScanRepository;
  /** Makes the knowledge base snapshot available locally (remote workers import a signed bundle). */
  prepareKnowledgeBase?(snapshotId: string | undefined): Promise<void>;
  signal?: AbortSignal;
}

const NEW_STATES = new Set(['NEW', 'REOPENED', 'NEEDS_RECONCILIATION']);

/** Runs a SCAN or REASSESS job; shared by the in-process worker and remote workers. */
export async function executeJob(
  job: JobEntry,
  project: ProjectEntry,
  rt: JobRuntime,
): Promise<Record<string, unknown>> {
  if (job.kind === 'SCAN') {
    const p = job.payload as unknown as ScanPayload;
    await rt.workspace.fetch(project, p.fetchRefs);
    const commit =
      project.source.kind === 'git'
        ? (p.commit ?? (await rt.workspace.resolve(project, p.ref ?? `refs/heads/${p.branch}`)))
        : undefined;
    await rt.prepareKnowledgeBase?.(undefined);
    return runInCheckout(job, project, rt, {
      commit,
      branch: p.branch,
      mode: p.mode ?? 'FULL',
      ...(p.diffBase ? { diffBase: p.diffBase } : {}),
    });
  }
  if (job.kind === 'REASSESS') {
    // Dependency-only re-run of the branch's last scanned commit against the new knowledge base.
    const branch = String(job.payload.branch);
    const repo = rt.repository(project.projectId);
    const engineProject = (await repo.getProject())?.project.projectId;
    const last = engineProject ? (await scansByBranch(repo, engineProject)).get(branch)?.[0] : undefined;
    if (!last) return { skipped: `branch ${branch} has no completed scan` };
    if (project.source.kind === 'git') await rt.workspace.fetch(project);
    const commit = project.source.kind === 'git' ? last.manifest.source.commitSha : undefined;
    if (project.source.kind === 'git' && !commit) return { skipped: `scan ${last.scanId} has no commit to reassess` };
    const kbSnapshotId = String(job.payload.kbSnapshotId ?? '') || undefined;
    await rt.prepareKnowledgeBase?.(kbSnapshotId);
    return runInCheckout(job, project, rt, {
      commit,
      branch,
      mode: 'DEPENDENCY_REASSESSMENT',
      ...(kbSnapshotId ? { kbSnapshotId } : {}),
    });
  }
  throw new Error(`job kind ${job.kind} is not run by scan workers`);
}

async function runInCheckout(
  job: JobEntry,
  project: ProjectEntry,
  rt: JobRuntime,
  run: { commit: string | undefined; branch: string; mode: ScanMode; diffBase?: string; kbSnapshotId?: string },
): Promise<Record<string, unknown>> {
  const checkout = await rt.workspace.checkout(project, run.commit, job.jobId);
  try {
    const engine = rt.engine({ projectId: project.projectId, sourceDir: checkout.dir });
    try {
      const outcome = await runScan(engine.deps, {
        projectName: project.name,
        mode: run.mode,
        exclude: [],
        baseline: { kind: 'auto' },
        reuseCache: true,
        branch: run.branch,
        ...(run.diffBase ? { diffBase: run.diffBase } : {}),
        ...(run.kbSnapshotId ? { kbSnapshotId: run.kbSnapshotId } : {}),
        ...(rt.signal ? { signal: rt.signal } : {}),
      });
      if (outcome.scan.status === 'FAILED') throw new Error(outcome.scan.error ?? 'scan failed');
      return {
        scanId: outcome.scan.scanId,
        status: outcome.scan.status,
        mode: run.mode,
        branch: run.branch,
        ...(checkout.commit ? { commit: checkout.commit } : {}),
        newFindings: outcome.assessments.filter((a) => NEW_STATES.has(a.reconciliationState)).map((a) => a.findingId),
        summary: outcome.scan.summary ?? null,
        tasks: outcome.tasks.map((t) => t.scannerId ?? t.kind),
      };
    } finally {
      engine.close();
    }
  } finally {
    await checkout.dispose();
  }
}
