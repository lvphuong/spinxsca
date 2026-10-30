/**
 * System-of-record tables (docs/architecture/02 section 8). Each row keeps the full validated domain
 * object in `data` plus the columns needed for lookups. Types are chosen to port to PostgreSQL
 * (ADR-019): text ids, ISO-8601 timestamps, JSON documents.
 */
import type {
  AgentRunRecord,
  AnalysisManifest,
  Coverage,
  Disposition,
  Evidence,
  FindingAssessment,
  FindingCandidate,
  FindingMatchEvent,
  FindingOccurrence,
  ScanSummary,
} from '@spinxsca/schemas';
import { index, integer, primaryKey, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core';

export const projects = sqliteTable('projects', {
  projectId: text('project_id').primaryKey(),
  name: text('name').notNull(),
  createdAt: text('created_at').notNull(),
});

export const repositories = sqliteTable('repositories', {
  repositoryId: text('repository_id').primaryKey(),
  projectId: text('project_id')
    .notNull()
    .references(() => projects.projectId),
  rootPath: text('root_path').notNull(),
  createdAt: text('created_at').notNull(),
});

export const sourceSnapshots = sqliteTable('source_snapshots', {
  snapshotId: text('snapshot_id').primaryKey(),
  repositoryId: text('repository_id')
    .notNull()
    .references(() => repositories.repositoryId),
  kind: text('kind').notNull(),
  commitSha: text('commit_sha'),
  treeSha: text('tree_sha'),
  branchAtCapture: text('branch_at_capture'),
  contentManifestDigest: text('content_manifest_digest').notNull(),
  fileCount: integer('file_count').notNull(),
  fileListDigest: text('file_list_digest').notNull(),
  capturedAt: text('captured_at').notNull(),
});

export const scanRuns = sqliteTable(
  'scan_runs',
  {
    scanId: text('scan_id').primaryKey(),
    projectId: text('project_id')
      .notNull()
      .references(() => projects.projectId),
    repositoryId: text('repository_id').notNull(),
    snapshotId: text('snapshot_id')
      .notNull()
      .references(() => sourceSnapshots.snapshotId),
    mode: text('mode').notNull(),
    status: text('status').notNull(),
    manifest: text('manifest', { mode: 'json' }).$type<AnalysisManifest>().notNull(),
    manifestDigest: text('manifest_digest').notNull(),
    baselineScanId: text('baseline_scan_id'),
    requestedAt: text('requested_at').notNull(),
    startedAt: text('started_at'),
    completedAt: text('completed_at'),
    summary: text('summary', { mode: 'json' }).$type<ScanSummary>(),
    error: text('error'),
  },
  (t) => [index('idx_scan_runs_project').on(t.projectId, t.requestedAt)],
);

export const scanTasks = sqliteTable(
  'scan_tasks',
  {
    taskId: text('task_id').primaryKey(),
    scanId: text('scan_id')
      .notNull()
      .references(() => scanRuns.scanId),
    kind: text('kind').notNull(),
    name: text('name').notNull(),
    scannerId: text('scanner_id'),
    idempotencyKey: text('idempotency_key').notNull(),
    status: text('status').notNull(),
    attempt: integer('attempt').notNull(),
    outputDigest: text('output_digest'),
    coverage: text('coverage', { mode: 'json' }).$type<Coverage>(),
    error: text('error'),
    startedAt: text('started_at'),
    completedAt: text('completed_at'),
  },
  (t) => [
    uniqueIndex('uq_scan_tasks_key').on(t.scanId, t.idempotencyKey),
    index('idx_scan_tasks_key').on(t.idempotencyKey, t.status),
  ],
);

export const findingCandidates = sqliteTable(
  'finding_candidates',
  {
    candidateId: text('candidate_id').primaryKey(),
    scanId: text('scan_id')
      .notNull()
      .references(() => scanRuns.scanId),
    scanTaskId: text('scan_task_id').notNull(),
    scanner: text('scanner').notNull(),
    ruleId: text('rule_id').notNull(),
    category: text('category').notNull(),
    semanticFingerprint: text('semantic_fingerprint').notNull(),
    data: text('data', { mode: 'json' }).$type<FindingCandidate>().notNull(),
  },
  (t) => [index('idx_candidates_scan').on(t.scanId)],
);

export const evidences = sqliteTable('evidences', {
  evidenceId: text('evidence_id').primaryKey(),
  kind: text('kind').notNull(),
  snapshotId: text('snapshot_id').notNull(),
  data: text('data', { mode: 'json' }).$type<Evidence>().notNull(),
});

export const findings = sqliteTable(
  'findings',
  {
    findingId: text('finding_id').primaryKey(),
    projectId: text('project_id')
      .notNull()
      .references(() => projects.projectId),
    seq: integer('seq').notNull(),
    category: text('category').notNull(),
    ruleFamily: text('rule_family').notNull(),
    title: text('title').notNull(),
    cwe: text('cwe', { mode: 'json' }).$type<string[]>().notNull(),
    canonicalFingerprint: text('canonical_fingerprint').notNull(),
    fingerprintAlgorithm: text('fingerprint_algorithm').notNull(),
    firstSeenScanId: text('first_seen_scan_id').notNull(),
    createdAt: text('created_at').notNull(),
  },
  (t) => [
    uniqueIndex('uq_findings_seq').on(t.projectId, t.seq),
    index('idx_findings_fp').on(t.projectId, t.canonicalFingerprint),
  ],
);

/** Canonical fingerprints and aliases recorded when a finding is relocated (rename, move). */
export const findingFingerprints = sqliteTable(
  'finding_fingerprints',
  {
    projectId: text('project_id').notNull(),
    fingerprint: text('fingerprint').notNull(),
    findingId: text('finding_id')
      .notNull()
      .references(() => findings.findingId),
    algorithm: text('algorithm').notNull(),
    createdAt: text('created_at').notNull(),
  },
  (t) => [primaryKey({ columns: [t.projectId, t.fingerprint] })],
);

export const findingOccurrences = sqliteTable(
  'finding_occurrences',
  {
    occurrenceId: text('occurrence_id').primaryKey(),
    findingId: text('finding_id')
      .notNull()
      .references(() => findings.findingId),
    scanId: text('scan_id')
      .notNull()
      .references(() => scanRuns.scanId),
    snapshotId: text('snapshot_id').notNull(),
    fingerprint: text('fingerprint').notNull(),
    data: text('data', { mode: 'json' }).$type<FindingOccurrence>().notNull(),
  },
  (t) => [index('idx_occurrences_scan').on(t.scanId), index('idx_occurrences_finding').on(t.findingId)],
);

export const findingAssessments = sqliteTable(
  'finding_assessments',
  {
    assessmentId: text('assessment_id').primaryKey(),
    findingId: text('finding_id')
      .notNull()
      .references(() => findings.findingId),
    scanId: text('scan_id')
      .notNull()
      .references(() => scanRuns.scanId),
    occurrenceId: text('occurrence_id'),
    reconciliationState: text('reconciliation_state').notNull(),
    severity: text('severity').notNull(),
    assessedAt: text('assessed_at').notNull(),
    data: text('data', { mode: 'json' }).$type<FindingAssessment>().notNull(),
  },
  (t) => [
    uniqueIndex('uq_assessment_scan_finding').on(t.scanId, t.findingId),
    index('idx_assessments_finding').on(t.findingId, t.assessedAt),
  ],
);

export const findingDispositions = sqliteTable(
  'finding_dispositions',
  {
    dispositionId: text('disposition_id').primaryKey(),
    findingId: text('finding_id')
      .notNull()
      .references(() => findings.findingId),
    kind: text('kind').notNull(),
    decidedAt: text('decided_at').notNull(),
    data: text('data', { mode: 'json' }).$type<Disposition>().notNull(),
  },
  (t) => [index('idx_dispositions_finding').on(t.findingId)],
);

export const findingMatchEvents = sqliteTable(
  'finding_match_events',
  {
    eventId: text('event_id').primaryKey(),
    scanId: text('scan_id')
      .notNull()
      .references(() => scanRuns.scanId),
    findingId: text('finding_id').notNull(),
    candidateId: text('candidate_id'),
    method: text('method').notNull(),
    decision: text('decision').notNull(),
    data: text('data', { mode: 'json' }).$type<FindingMatchEvent>().notNull(),
  },
  (t) => [index('idx_match_events_scan').on(t.scanId)],
);

/** Branch/release baselines (ADR-015); managed by `spinxsca baseline set` from phase 1. */
export const baselines = sqliteTable(
  'baselines',
  {
    baselineId: text('baseline_id').primaryKey(),
    projectId: text('project_id')
      .notNull()
      .references(() => projects.projectId),
    scopeType: text('scope_type').notNull(),
    scopeRef: text('scope_ref').notNull(),
    scanId: text('scan_id')
      .notNull()
      .references(() => scanRuns.scanId),
    reason: text('reason').notNull(),
    activatedAt: text('activated_at').notNull(),
    deactivatedAt: text('deactivated_at'),
  },
  (t) => [index('idx_baselines_scope').on(t.projectId, t.scopeType, t.scopeRef)],
);

/** Audit trail of AI runs (docs/architecture/03 section 8): usage, cost, models, output; no hidden reasoning. */
export const agentRuns = sqliteTable(
  'agent_runs',
  {
    agentRunId: text('agent_run_id').primaryKey(),
    role: text('role').notNull(),
    scanId: text('scan_id'),
    findingId: text('finding_id'),
    status: text('status').notNull(),
    startedAt: text('started_at').notNull(),
    data: text('data', { mode: 'json' }).$type<AgentRunRecord>().notNull(),
  },
  (t) => [index('idx_agent_runs_scan').on(t.scanId), index('idx_agent_runs_finding').on(t.findingId, t.startedAt)],
);
