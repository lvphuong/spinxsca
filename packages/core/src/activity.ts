import type { Coverage, Digest, ScanTask, TaskKind } from '@spinxsca/schemas';
import { errorMessage, throwIfAborted } from './errors';
import { newId } from './ids';
import type { ArtifactStore, Clock, Logger, ScanRepository } from './ports';

/**
 * One unit of side-effecting work (ADR-017). Activities are idempotent by key, persist their
 * output as an artifact and can be replayed from a checkpoint. In phase 4 each activity maps 1:1 to
 * a Temporal activity.
 */
export interface Activity<I, O> {
  readonly name: string;
  readonly kind: TaskKind;
  idempotencyKey(input: I): string;
  run(input: I, ctx: ActivityContext): Promise<ActivityOutput<O>>;
}

export interface ActivityOutput<O> {
  output: O;
  coverage?: Coverage;
  /** PARTIAL when the activity produced usable output but did not cover its full scope. */
  status?: 'SUCCEEDED' | 'PARTIAL';
}

export interface ActivityContext {
  scanId: string;
  taskId: string;
  logger: Logger;
  artifacts: ArtifactStore;
  clock: Clock;
  signal?: AbortSignal;
}

export interface ActivityRunnerDeps {
  repo: ScanRepository;
  artifacts: ArtifactStore;
  logger: Logger;
  clock: Clock;
  signal?: AbortSignal;
  /** Reuse a succeeded task with the same key from an earlier scan. */
  reuseAcrossScans: boolean;
}

export interface ActivityResult<O> {
  task: ScanTask;
  output?: O;
  reused: boolean;
}

/**
 * Runs an activity with checkpointing: a succeeded task with the same idempotency key in this scan
 * (resume) or, when allowed, in an earlier scan (cache) is reused instead of re-executed.
 */
export async function runActivity<I, O>(
  deps: ActivityRunnerDeps,
  scanId: string,
  activity: Activity<I, O>,
  input: I,
  meta: { scannerId?: string } = {},
): Promise<ActivityResult<O>> {
  const key = activity.idempotencyKey(input);
  const existing = (await deps.repo.listTasks(scanId)).find((t) => t.idempotencyKey === key);
  if (existing && isReusable(existing)) {
    return { task: existing, output: await loadOutput<O>(deps.artifacts, existing.outputDigest), reused: true };
  }
  if (deps.reuseAcrossScans) {
    const cached = await deps.repo.findReusableTask(key);
    if (cached && isReusable(cached) && (await deps.artifacts.has(cached.outputDigest as Digest))) {
      const now = deps.clock.now().toISOString();
      const task: ScanTask = {
        ...cached,
        taskId: existing?.taskId ?? newId('task'),
        scanId,
        attempt: (existing?.attempt ?? 0) + 1,
        startedAt: now,
        completedAt: now,
      };
      await deps.repo.upsertTask(task);
      deps.logger.info(`reused ${activity.name} output from scan ${cached.scanId}`, { task: task.taskId });
      return { task, output: await loadOutput<O>(deps.artifacts, cached.outputDigest), reused: true };
    }
  }

  const task: ScanTask = {
    taskId: existing?.taskId ?? newId('task'),
    scanId,
    kind: activity.kind,
    name: activity.name,
    ...(meta.scannerId ? { scannerId: meta.scannerId } : {}),
    idempotencyKey: key,
    status: 'RUNNING',
    attempt: (existing?.attempt ?? 0) + 1,
    startedAt: deps.clock.now().toISOString(),
  };
  await deps.repo.upsertTask(task);
  try {
    throwIfAborted(deps.signal);
    const ctx: ActivityContext = {
      scanId,
      taskId: task.taskId,
      logger: deps.logger,
      artifacts: deps.artifacts,
      clock: deps.clock,
      ...(deps.signal ? { signal: deps.signal } : {}),
    };
    const result = await activity.run(input, ctx);
    const ref = await deps.artifacts.put(JSON.stringify(result.output), 'application/json');
    const done: ScanTask = {
      ...task,
      status: result.status ?? 'SUCCEEDED',
      outputDigest: ref.digest,
      ...(result.coverage ? { coverage: result.coverage } : {}),
      completedAt: deps.clock.now().toISOString(),
    };
    await deps.repo.upsertTask(done);
    return { task: done, output: result.output, reused: false };
  } catch (err) {
    const failed: ScanTask = {
      ...task,
      status: deps.signal?.aborted ? 'CANCELLED' : 'FAILED',
      error: errorMessage(err),
      completedAt: deps.clock.now().toISOString(),
    };
    await deps.repo.upsertTask(failed);
    deps.logger.error(`${activity.name} failed: ${failed.error}`, { task: task.taskId });
    return { task: failed, reused: false };
  }
}

function isReusable(task: ScanTask): task is ScanTask & { outputDigest: Digest } {
  return (task.status === 'SUCCEEDED' || task.status === 'PARTIAL') && task.outputDigest !== undefined;
}

async function loadOutput<O>(artifacts: ArtifactStore, digest: Digest | undefined): Promise<O | undefined> {
  if (!digest) return undefined;
  return JSON.parse(await artifacts.getText(digest)) as O;
}
