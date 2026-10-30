import { proxyActivities } from '@temporalio/workflow';
import type { JobActivities, JobOutcome, JobWorkflowInput } from './types';

/**
 * One spinxsca job as a durable workflow (docs/architecture/06 section 3.1, ADR-038). The activity is
 * idempotent: it re-claims the job with a new fencing token, and a job that already finished is
 * returned as is. Retries follow the registry's attempt budget (3).
 */
export async function jobWorkflow(input: JobWorkflowInput): Promise<JobOutcome> {
  const { runJob } = proxyActivities<JobActivities>({
    startToCloseTimeout: '6 hours',
    heartbeatTimeout: '2 minutes',
    retry: {
      initialInterval: `${input.retryInitialIntervalSeconds ?? 30} seconds`,
      backoffCoefficient: 5,
      maximumAttempts: 3,
      nonRetryableErrorTypes: ['JobNotFound', 'JobFailed'],
    },
  });
  return runJob(input.jobId);
}
