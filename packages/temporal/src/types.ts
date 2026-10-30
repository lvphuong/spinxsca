/** Shared between workflow code (sandboxed) and the host; keep free of runtime imports. */
export interface JobOutcome {
  jobId: string;
  status: string;
  result?: Record<string, unknown>;
}

export interface JobWorkflowInput {
  jobId: string;
  /** First retry delay (default 30 s, then x5). */
  retryInitialIntervalSeconds?: number;
}

export interface JobActivities {
  runJob(jobId: string): Promise<JobOutcome>;
}

export const DEFAULT_TASK_QUEUE = 'spinxsca-jobs';
export const workflowIdFor = (jobId: string) => `spinxsca-job-${jobId}`;
