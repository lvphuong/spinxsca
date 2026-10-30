import { fileURLToPath } from 'node:url';
import type { Logger } from '@spinxsca/core';
import type { JobDispatcher, JobEntry, Worker as ServerWorker } from '@spinxsca/server';
import { Client, Connection, WorkflowExecutionAlreadyStartedError } from '@temporalio/client';
import { DefaultLogger, NativeConnection, Runtime, Worker } from '@temporalio/worker';
import { createActivities } from './activities';
import { DEFAULT_TASK_QUEUE, workflowIdFor } from './types';

export interface TemporalOptions {
  address: string;
  namespace?: string;
  taskQueue?: string;
  retryInitialIntervalSeconds?: number;
}

/** Starts one workflow per job (workflow id derived from the job id, so dispatch is idempotent). */
export class TemporalDispatcher implements JobDispatcher {
  private constructor(
    private readonly connection: Connection,
    private readonly client: Client,
    private readonly taskQueue: string,
    readonly pools: readonly string[],
    private readonly retryInitialIntervalSeconds?: number,
  ) {}

  static async connect(options: TemporalOptions & { pools: readonly string[] }): Promise<TemporalDispatcher> {
    const connection = await Connection.connect({ address: options.address });
    const client = new Client({ connection, namespace: options.namespace ?? 'default' });
    return new TemporalDispatcher(
      connection,
      client,
      options.taskQueue ?? DEFAULT_TASK_QUEUE,
      options.pools,
      options.retryInitialIntervalSeconds,
    );
  }

  async dispatch(job: JobEntry): Promise<void> {
    try {
      await this.client.workflow.start('jobWorkflow', {
        taskQueue: this.taskQueue,
        workflowId: workflowIdFor(job.jobId),
        args: [
          {
            jobId: job.jobId,
            ...(this.retryInitialIntervalSeconds
              ? { retryInitialIntervalSeconds: this.retryInitialIntervalSeconds }
              : {}),
          },
        ],
        memo: { kind: job.kind, projectId: job.projectId ?? '', pool: job.pool },
      });
    } catch (err) {
      if (!(err instanceof WorkflowExecutionAlreadyStartedError)) throw err;
    }
  }

  /** Requests cancellation; the running activity aborts its scan and the job is recorded as failed. */
  async cancel(jobId: string): Promise<void> {
    await this.client.workflow.getHandle(workflowIdFor(jobId)).cancel();
  }

  async result(jobId: string): Promise<unknown> {
    return this.client.workflow.getHandle(workflowIdFor(jobId)).result();
  }

  async close(): Promise<void> {
    await this.connection.close();
  }
}

export interface RunningTemporalWorker {
  shutdown(): Promise<void>;
  /** Resolves when the worker stops. */
  done: Promise<void>;
}

/**
 * Temporal worker hosting the job activities. Workflow code is bundled from source (tests, `tsx`) or
 * loaded from a prebuilt bundle shipped with the CLI.
 */
export async function startTemporalWorker(
  options: TemporalOptions & {
    worker: ServerWorker;
    logger: Logger;
    workflowBundlePath?: string;
    maxConcurrentActivities?: number;
  },
): Promise<RunningTemporalWorker> {
  installRuntime(options.logger);
  const connection = await NativeConnection.connect({ address: options.address });
  const worker = await Worker.create({
    connection,
    namespace: options.namespace ?? 'default',
    taskQueue: options.taskQueue ?? DEFAULT_TASK_QUEUE,
    activities: createActivities(options.worker),
    maxConcurrentActivityTaskExecutions: options.maxConcurrentActivities ?? 1,
    ...(options.workflowBundlePath
      ? { workflowBundle: { codePath: options.workflowBundlePath } }
      : { workflowsPath: fileURLToPath(new URL('./workflows.ts', import.meta.url)) }),
  });
  const done = worker.run().finally(() => connection.close());
  return {
    done,
    shutdown: async () => {
      if (worker.getState() === 'RUNNING') worker.shutdown();
      await done;
    },
  };
}

let runtimeInstalled = false;
/** The Temporal runtime is process-wide and can be installed once; its warnings go to our logger. */
function installRuntime(logger: Logger): void {
  if (runtimeInstalled) return;
  runtimeInstalled = true;
  Runtime.install({
    logger: new DefaultLogger('WARN', (entry) =>
      entry.level === 'ERROR' ? logger.error(entry.message) : logger.warn(entry.message),
    ),
    // The host process owns signal handling and shuts the worker down itself.
    shutdownSignals: [],
  });
}
