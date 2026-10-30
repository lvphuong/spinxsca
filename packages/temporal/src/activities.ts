import type { Worker as ServerWorker } from '@spinxsca/server';
import { Context } from '@temporalio/activity';
import { ApplicationFailure } from '@temporalio/common';
import type { JobActivities } from './types';

/**
 * Activities run the job through the server's job runner, so a Temporal-orchestrated job records its
 * status, result, lease and audit trail in the registry exactly like a polled one.
 */
export function createActivities(worker: ServerWorker): JobActivities {
  return {
    async runJob(jobId) {
      const ctx = Context.current();
      const beat = setInterval(() => ctx.heartbeat(), 20_000);
      try {
        const job = await worker.runJob(
          jobId,
          ctx.cancellationSignal,
          `temporal:${ctx.info.workflowExecution?.workflowId ?? ctx.info.activityId}`,
        );
        if (!job) throw ApplicationFailure.nonRetryable(`job ${jobId} not found`, 'JobNotFound');
        if (job.status === 'SUCCEEDED')
          return { jobId, status: job.status, ...(job.result ? { result: job.result } : {}) };
        if (job.status === 'RUNNING')
          throw ApplicationFailure.retryable(`job ${jobId} is leased by another worker`, 'JobBusy');
        if (job.status === 'FAILED' || job.status === 'CANCELLED')
          throw ApplicationFailure.nonRetryable(job.error ?? `job ${job.status.toLowerCase()}`, 'JobFailed');
        throw ApplicationFailure.retryable(job.error ?? 'job failed; retrying', 'JobRetry');
      } finally {
        clearInterval(beat);
      }
    },
  };
}
