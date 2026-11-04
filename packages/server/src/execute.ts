import {
  type AiScanOptions,
  type ArtifactStore,
  type AutonomousReviewer,
  type CaseRepository,
  type ReviewPortContext,
  type ReviewPorts,
  runScan,
  type ScanDeps,
  type ScanRepository,
  scansByBranch,
} from '@spinxsca/core';
import type { ScanMode } from '@spinxsca/schemas';
import type { NotificationEvent } from './notify';
import type { JobEntry, ProjectEntry } from './registry';
import type { ProjectWorkspace } from './workspace';

/** Scan engine for one source directory (built by the CLI runtime). */
export interface ScanEngine {
  deps: ScanDeps;
  close(): void;
  /** AI configured for this server (operator configuration); absent when AI is off. */
  ai?: AiScanOptions;
  /** Autonomous review for REVIEW / CASE_RESUME jobs; always unattended here (asks park in the inbox). */
  review?: (input: { goal?: string; objectives?: readonly string[] }) => {
    reviewer: AutonomousReviewer;
    ports: (ctx: ReviewPortContext) => Promise<ReviewPorts>;
  };
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
  /** Case store of the project (control plane RPC for remote workers). */
  cases?: CaseRepository;
}) => ScanEngine;

export interface ReviewPayload {
  branch: string;
  commit?: string;
  ref?: string;
  fetchRefs?: Array<{ remote: string; local: string }>;
  goal?: string;
  objectives?: string[];
}

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
  /** Case store of a project (REVIEW and CASE_RESUME jobs). */
  cases?(projectId: string): CaseRepository;
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
      ...(project.ai ? { aiLevel: project.ai.level } : {}),
    });
  }
  if (job.kind === 'REVIEW') {
    // Autonomous review of a branch (ADR-047): a full scan with an unattended review case.
    const p = job.payload as unknown as ReviewPayload;
    await rt.workspace.fetch(project, p.fetchRefs);
    const commit =
      project.source.kind === 'git'
        ? (p.commit ?? (await rt.workspace.resolve(project, p.ref ?? `refs/heads/${p.branch}`)))
        : undefined;
    await rt.prepareKnowledgeBase?.(undefined);
    return runInCheckout(job, project, rt, {
      commit,
      branch: p.branch,
      mode: 'FULL',
      aiLevel: 'deep',
      review: {
        ...((p.goal ?? project.ai?.goal) ? { goal: p.goal ?? project.ai?.goal } : {}),
        ...((p.objectives ?? project.ai?.objectives) ? { objectives: p.objectives ?? project.ai?.objectives } : {}),
      },
    });
  }
  if (job.kind === 'CASE_RESUME') {
    // A human answered an approval: continue the same case on the same commit (ADR-047).
    const caseId = String(job.payload.caseId ?? '');
    const cases = rt.cases?.(project.projectId);
    const rc = caseId && cases ? await cases.getCase(caseId) : undefined;
    if (!rc) return { skipped: `case ${caseId} not found` };
    if (['CONVERGED', 'STAGNATED', 'CANCELLED', 'FAILED'].includes(rc.status))
      return { skipped: `case ${caseId} is ${rc.status}` };
    const scan = await rt.repository(project.projectId).getScan(rc.scanId);
    if (!scan) return { skipped: `scan ${rc.scanId} of case ${caseId} not found` };
    if (project.source.kind === 'git') await rt.workspace.fetch(project);
    const commit = project.source.kind === 'git' ? scan.manifest.source.commitSha : undefined;
    await rt.prepareKnowledgeBase?.(scan.manifest.knowledgeBase?.snapshotId);
    return runInCheckout(job, project, rt, {
      commit,
      branch: scan.manifest.source.branch ?? project.defaultBranch,
      mode: 'FULL',
      aiLevel: 'deep',
      review: { goal: rc.goal, caseId },
      ...(scan.manifest.knowledgeBase?.snapshotId ? { kbSnapshotId: scan.manifest.knowledgeBase.snapshotId } : {}),
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
  run: {
    commit: string | undefined;
    branch: string;
    mode: ScanMode;
    diffBase?: string;
    kbSnapshotId?: string;
    aiLevel?: AiScanOptions['level'];
    review?: { goal?: string; objectives?: readonly string[]; caseId?: string };
  },
): Promise<Record<string, unknown>> {
  const checkout = await rt.workspace.checkout(project, run.commit, job.jobId);
  try {
    const engine = rt.engine({ projectId: project.projectId, sourceDir: checkout.dir });
    try {
      // Dependency reassessments never call a model; other jobs use the project or server AI level.
      const level = run.mode === 'DEPENDENCY_REASSESSMENT' ? 'off' : (run.aiLevel ?? engine.ai?.level ?? 'off');
      const ai = level !== 'off' && engine.ai ? { ...engine.ai, level } : undefined;
      if (level === 'deep' && (!engine.review || !ai))
        throw new Error('autonomous review needs AI configured on this server');
      const review = level === 'deep' && engine.review ? engine.review(run.review ?? {}) : undefined;
      const deps: ScanDeps = review
        ? { ...engine.deps, reviewer: review.reviewer, reviewPorts: review.ports }
        : engine.deps;
      const outcome = await runScan(deps, {
        projectName: project.name,
        mode: run.mode,
        exclude: [],
        baseline: { kind: 'auto' },
        reuseCache: true,
        branch: run.branch,
        ...(run.diffBase ? { diffBase: run.diffBase } : {}),
        ...(run.kbSnapshotId ? { kbSnapshotId: run.kbSnapshotId } : {}),
        ...(ai ? { ai } : {}),
        ...(run.review?.caseId ? { reviewCaseId: run.review.caseId } : {}),
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
        ...(outcome.ai?.review ? { review: outcome.ai.review } : {}),
      };
    } finally {
      engine.close();
    }
  } finally {
    await checkout.dispose();
  }
}
