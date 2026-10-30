import { z } from 'zod';
import { Digest, Severity, Timestamp } from './common';
import { Completeness, Coverage } from './coverage';
import { ReconciliationState } from './finding';
import { AnalysisManifest, ScanMode } from './manifest';

export const ScanStatus = z.enum(['QUEUED', 'RUNNING', 'COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED']);
export type ScanStatus = z.infer<typeof ScanStatus>;

export const TaskStatus = z.enum([
  'PENDING',
  'RUNNING',
  'SUCCEEDED',
  'PARTIAL',
  'FAILED',
  'CANCELLED',
  'TIMED_OUT',
  'SKIPPED',
]);
export type TaskStatus = z.infer<typeof TaskStatus>;

export const ScanSummary = z.object({
  candidates: z.number().int().nonnegative(),
  findings: z.number().int().nonnegative(),
  bySeverity: z.partialRecord(Severity, z.number().int().nonnegative()),
  byState: z.partialRecord(ReconciliationState, z.number().int().nonnegative()),
  completeness: Completeness,
});
export type ScanSummary = z.infer<typeof ScanSummary>;

export const ScanRun = z.object({
  scanId: z.string(),
  projectId: z.string(),
  repositoryId: z.string(),
  snapshotId: z.string(),
  mode: ScanMode,
  status: ScanStatus,
  manifest: AnalysisManifest,
  manifestDigest: Digest,
  baselineScanId: z.string().optional(),
  requestedAt: Timestamp,
  startedAt: Timestamp.optional(),
  completedAt: Timestamp.optional(),
  summary: ScanSummary.optional(),
  error: z.string().optional(),
});
export type ScanRun = z.infer<typeof ScanRun>;

export const TaskKind = z.enum(['SNAPSHOT', 'SCANNER', 'RECONCILE', 'REPORT', 'AGENT', 'INDEX', 'IMPACT']);
export type TaskKind = z.infer<typeof TaskKind>;

export const ScanTask = z.object({
  taskId: z.string(),
  scanId: z.string(),
  kind: TaskKind,
  name: z.string(),
  scannerId: z.string().optional(),
  /** Deterministic key: re-running a task with the same key must not create duplicate output. */
  idempotencyKey: z.string(),
  status: TaskStatus,
  attempt: z.number().int().nonnegative(),
  outputDigest: Digest.optional(),
  coverage: Coverage.optional(),
  error: z.string().optional(),
  startedAt: Timestamp.optional(),
  completedAt: Timestamp.optional(),
});
export type ScanTask = z.infer<typeof ScanTask>;
