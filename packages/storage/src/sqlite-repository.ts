import {
  type BaselineRecord,
  newId,
  type ProjectRecord,
  type ReconciliationCommit,
  type RepositoryRecord,
  type ScanRepository,
} from '@spinxsca/core';
import {
  AgentRunRecord,
  Disposition,
  Evidence,
  Finding,
  FindingAssessment,
  FindingCandidate,
  FindingMatchEvent,
  FindingOccurrence,
  ScanRun,
  type ScanStatus,
  ScanTask,
  SourceSnapshot,
} from '@spinxsca/schemas';
import Database from 'better-sqlite3';
import { and, asc, desc, eq, inArray, isNull, max, ne } from 'drizzle-orm';
import { type BetterSQLite3Database, drizzle } from 'drizzle-orm/better-sqlite3';
import { migrate } from './migrate';
import * as t from './schema';

const CHUNK = 200;

/** SQLite system of record for the local CLI (ADR-019). */
export class SqliteScanRepository implements ScanRepository {
  private constructor(
    private readonly sqlite: Database.Database,
    private readonly db: BetterSQLite3Database<typeof t>,
  ) {}

  static open(path: string): SqliteScanRepository {
    const sqlite = new Database(path);
    sqlite.pragma('journal_mode = WAL');
    sqlite.pragma('foreign_keys = ON');
    sqlite.pragma('busy_timeout = 5000');
    migrate(sqlite);
    return new SqliteScanRepository(sqlite, drizzle({ client: sqlite, schema: t }));
  }

  close(): void {
    this.sqlite.close();
  }

  async ensureProject(input: {
    name: string;
    rootPath: string;
  }): Promise<{ project: ProjectRecord; repository: RepositoryRecord }> {
    const existing = await this.getProject();
    if (existing) return existing;
    const createdAt = new Date().toISOString();
    const project: ProjectRecord = { projectId: newId('prj'), name: input.name, createdAt };
    const repository: RepositoryRecord = {
      repositoryId: newId('repo'),
      projectId: project.projectId,
      rootPath: input.rootPath,
      createdAt,
    };
    this.db.transaction((tx) => {
      tx.insert(t.projects).values(project).run();
      tx.insert(t.repositories).values(repository).run();
    });
    return { project, repository };
  }

  async getProject(): Promise<{ project: ProjectRecord; repository: RepositoryRecord } | undefined> {
    const project = this.db.select().from(t.projects).orderBy(asc(t.projects.createdAt)).limit(1).get();
    if (!project) return undefined;
    const repository = this.db
      .select()
      .from(t.repositories)
      .where(eq(t.repositories.projectId, project.projectId))
      .orderBy(asc(t.repositories.createdAt))
      .limit(1)
      .get();
    if (!repository) return undefined;
    return { project, repository };
  }

  async saveSnapshot(snapshot: SourceSnapshot): Promise<void> {
    this.db
      .insert(t.sourceSnapshots)
      .values({
        snapshotId: snapshot.snapshotId,
        repositoryId: snapshot.repositoryId,
        kind: snapshot.kind,
        commitSha: snapshot.commitSha ?? null,
        treeSha: snapshot.treeSha ?? null,
        branchAtCapture: snapshot.branchAtCapture ?? null,
        contentManifestDigest: snapshot.contentManifestDigest,
        fileCount: snapshot.fileCount,
        fileListDigest: snapshot.fileListDigest,
        capturedAt: snapshot.capturedAt,
      })
      .onConflictDoNothing()
      .run();
  }

  async getSnapshot(snapshotId: string): Promise<SourceSnapshot | undefined> {
    const row = this.db.select().from(t.sourceSnapshots).where(eq(t.sourceSnapshots.snapshotId, snapshotId)).get();
    return row ? SourceSnapshot.parse(stripNulls(row)) : undefined;
  }

  async createScan(scan: ScanRun): Promise<void> {
    this.db
      .insert(t.scanRuns)
      .values({
        scanId: scan.scanId,
        projectId: scan.projectId,
        repositoryId: scan.repositoryId,
        snapshotId: scan.snapshotId,
        mode: scan.mode,
        status: scan.status,
        manifest: scan.manifest,
        manifestDigest: scan.manifestDigest,
        baselineScanId: scan.baselineScanId ?? null,
        requestedAt: scan.requestedAt,
        startedAt: scan.startedAt ?? null,
        completedAt: scan.completedAt ?? null,
        summary: scan.summary ?? null,
        error: scan.error ?? null,
      })
      .run();
  }

  async updateScan(
    scanId: string,
    patch: Partial<Pick<ScanRun, 'status' | 'startedAt' | 'completedAt' | 'summary' | 'error'>>,
  ): Promise<void> {
    this.db.update(t.scanRuns).set(patch).where(eq(t.scanRuns.scanId, scanId)).run();
  }

  async getScan(scanId: string): Promise<ScanRun | undefined> {
    const row = this.db.select().from(t.scanRuns).where(eq(t.scanRuns.scanId, scanId)).get();
    return row ? ScanRun.parse(stripNulls(row)) : undefined;
  }

  async listScans(projectId: string, limit = 50): Promise<ScanRun[]> {
    return this.db
      .select()
      .from(t.scanRuns)
      .where(eq(t.scanRuns.projectId, projectId))
      .orderBy(desc(t.scanRuns.requestedAt), desc(t.scanRuns.scanId))
      .limit(limit)
      .all()
      .map((row) => ScanRun.parse(stripNulls(row)));
  }

  async latestScan(
    projectId: string,
    statuses: readonly ScanStatus[],
    excludeScanId?: string,
  ): Promise<ScanRun | undefined> {
    const row = this.db
      .select()
      .from(t.scanRuns)
      .where(
        and(
          eq(t.scanRuns.projectId, projectId),
          inArray(t.scanRuns.status, [...statuses]),
          excludeScanId ? ne(t.scanRuns.scanId, excludeScanId) : undefined,
        ),
      )
      .orderBy(desc(t.scanRuns.requestedAt), desc(t.scanRuns.scanId))
      .limit(1)
      .get();
    return row ? ScanRun.parse(stripNulls(row)) : undefined;
  }

  async upsertTask(task: ScanTask): Promise<void> {
    const values = {
      taskId: task.taskId,
      scanId: task.scanId,
      kind: task.kind,
      name: task.name,
      scannerId: task.scannerId ?? null,
      idempotencyKey: task.idempotencyKey,
      status: task.status,
      attempt: task.attempt,
      outputDigest: task.outputDigest ?? null,
      coverage: task.coverage ?? null,
      error: task.error ?? null,
      startedAt: task.startedAt ?? null,
      completedAt: task.completedAt ?? null,
    };
    const { taskId: _id, ...update } = values;
    this.db.insert(t.scanTasks).values(values).onConflictDoUpdate({ target: t.scanTasks.taskId, set: update }).run();
  }

  async listTasks(scanId: string): Promise<ScanTask[]> {
    return this.db
      .select()
      .from(t.scanTasks)
      .where(eq(t.scanTasks.scanId, scanId))
      .orderBy(asc(t.scanTasks.taskId))
      .all()
      .map((row) => ScanTask.parse(stripNulls(row)));
  }

  async findReusableTask(idempotencyKey: string): Promise<ScanTask | undefined> {
    const row = this.db
      .select()
      .from(t.scanTasks)
      .where(and(eq(t.scanTasks.idempotencyKey, idempotencyKey), inArray(t.scanTasks.status, ['SUCCEEDED', 'PARTIAL'])))
      .orderBy(desc(t.scanTasks.completedAt))
      .limit(1)
      .get();
    return row ? ScanTask.parse(stripNulls(row)) : undefined;
  }

  async saveCandidates(candidates: FindingCandidate[]): Promise<void> {
    this.db.transaction((tx) => {
      for (const chunk of chunks(candidates)) {
        tx.insert(t.findingCandidates)
          .values(
            chunk.map((c) => ({
              candidateId: c.candidateId,
              scanId: c.scanId,
              scanTaskId: c.scanTaskId,
              scanner: c.scanner,
              ruleId: c.ruleId,
              category: c.category,
              semanticFingerprint: c.fingerprints.semantic,
              data: c,
            })),
          )
          .onConflictDoNothing()
          .run();
      }
    });
  }

  async listCandidates(scanId: string): Promise<FindingCandidate[]> {
    return this.db
      .select({ data: t.findingCandidates.data })
      .from(t.findingCandidates)
      .where(eq(t.findingCandidates.scanId, scanId))
      .orderBy(asc(t.findingCandidates.candidateId))
      .all()
      .map((row) => FindingCandidate.parse(row.data));
  }

  async saveEvidence(evidence: Evidence[]): Promise<void> {
    this.db.transaction((tx) => {
      for (const chunk of chunks(evidence)) {
        tx.insert(t.evidences)
          .values(chunk.map((e) => ({ evidenceId: e.evidenceId, kind: e.kind, snapshotId: e.snapshotId, data: e })))
          .onConflictDoNothing()
          .run();
      }
    });
  }

  async getEvidence(ids: readonly string[]): Promise<Evidence[]> {
    if (ids.length === 0) return [];
    const rows = this.db
      .select({ data: t.evidences.data })
      .from(t.evidences)
      .where(inArray(t.evidences.evidenceId, [...ids]))
      .all();
    const byId = new Map(rows.map((r) => [r.data.evidenceId, Evidence.parse(r.data)]));
    return ids.map((id) => byId.get(id)).filter((e): e is Evidence => e !== undefined);
  }

  async nextFindingSeq(projectId: string): Promise<number> {
    const row = this.db
      .select({ value: max(t.findings.seq) })
      .from(t.findings)
      .where(eq(t.findings.projectId, projectId))
      .get();
    return (row?.value ?? 0) + 1;
  }

  async listFindings(projectId: string): Promise<Finding[]> {
    return this.db
      .select()
      .from(t.findings)
      .where(eq(t.findings.projectId, projectId))
      .orderBy(asc(t.findings.seq))
      .all()
      .map((row) => Finding.parse(row));
  }

  async getFinding(findingId: string): Promise<Finding | undefined> {
    const row = this.db.select().from(t.findings).where(eq(t.findings.findingId, findingId)).get();
    return row ? Finding.parse(row) : undefined;
  }

  async fingerprintIndex(projectId: string): Promise<Map<string, string>> {
    const rows = this.db
      .select({ fingerprint: t.findingFingerprints.fingerprint, findingId: t.findingFingerprints.findingId })
      .from(t.findingFingerprints)
      .where(eq(t.findingFingerprints.projectId, projectId))
      .all();
    return new Map(rows.map((r) => [r.fingerprint, r.findingId]));
  }

  async commitReconciliation(scanId: string, commit: ReconciliationCommit): Promise<void> {
    const scan = await this.getScan(scanId);
    if (!scan) throw new Error(`scan ${scanId} not found`);
    const now = new Date().toISOString();
    this.db.transaction((tx) => {
      for (const finding of commit.newFindings) {
        tx.insert(t.findings).values(finding).run();
        tx.insert(t.findingFingerprints)
          .values({
            projectId: finding.projectId,
            fingerprint: finding.canonicalFingerprint,
            findingId: finding.findingId,
            algorithm: finding.fingerprintAlgorithm,
            createdAt: now,
          })
          .onConflictDoNothing()
          .run();
      }
      for (const alias of commit.fingerprintAliases) {
        tx.insert(t.findingFingerprints)
          .values({ projectId: scan.projectId, ...alias, createdAt: now })
          .onConflictDoNothing()
          .run();
      }
      for (const chunk of chunks(commit.occurrences)) {
        tx.insert(t.findingOccurrences)
          .values(
            chunk.map((o) => ({
              occurrenceId: o.occurrenceId,
              findingId: o.findingId,
              scanId: o.scanId,
              snapshotId: o.snapshotId,
              fingerprint: o.fingerprint,
              data: o,
            })),
          )
          .run();
      }
      for (const chunk of chunks(commit.assessments)) {
        tx.insert(t.findingAssessments)
          .values(
            chunk.map((a) => ({
              assessmentId: a.assessmentId,
              findingId: a.findingId,
              scanId: a.scanId,
              occurrenceId: a.occurrenceId ?? null,
              reconciliationState: a.reconciliationState,
              severity: a.severity,
              assessedAt: a.assessedAt,
              data: a,
            })),
          )
          .run();
      }
      for (const chunk of chunks(commit.matchEvents)) {
        tx.insert(t.findingMatchEvents)
          .values(
            chunk.map((e) => ({
              eventId: e.eventId,
              scanId: e.scanId,
              findingId: e.findingId,
              candidateId: e.candidateId ?? null,
              method: e.method,
              decision: e.decision,
              data: e,
            })),
          )
          .run();
      }
    });
  }

  async listOccurrences(scanId: string): Promise<FindingOccurrence[]> {
    return this.db
      .select({ data: t.findingOccurrences.data })
      .from(t.findingOccurrences)
      .where(eq(t.findingOccurrences.scanId, scanId))
      .orderBy(asc(t.findingOccurrences.occurrenceId))
      .all()
      .map((r) => FindingOccurrence.parse(r.data));
  }

  async occurrencesForFinding(findingId: string): Promise<FindingOccurrence[]> {
    return this.db
      .select({ data: t.findingOccurrences.data })
      .from(t.findingOccurrences)
      .where(eq(t.findingOccurrences.findingId, findingId))
      .orderBy(asc(t.findingOccurrences.occurrenceId))
      .all()
      .map((r) => FindingOccurrence.parse(r.data));
  }

  async listAssessments(scanId: string): Promise<FindingAssessment[]> {
    return this.db
      .select({ data: t.findingAssessments.data })
      .from(t.findingAssessments)
      .where(eq(t.findingAssessments.scanId, scanId))
      .orderBy(asc(t.findingAssessments.findingId))
      .all()
      .map((r) => FindingAssessment.parse(r.data));
  }

  async assessmentsForFinding(findingId: string): Promise<FindingAssessment[]> {
    return this.db
      .select({ data: t.findingAssessments.data })
      .from(t.findingAssessments)
      .where(eq(t.findingAssessments.findingId, findingId))
      .orderBy(asc(t.findingAssessments.assessedAt), asc(t.findingAssessments.assessmentId))
      .all()
      .map((r) => FindingAssessment.parse(r.data));
  }

  async latestByFinding(
    projectId: string,
  ): Promise<Map<string, { assessment?: FindingAssessment; occurrence?: FindingOccurrence }>> {
    const result = new Map<string, { assessment?: FindingAssessment; occurrence?: FindingOccurrence }>();
    const assessments = this.db
      .select({ data: t.findingAssessments.data })
      .from(t.findingAssessments)
      .innerJoin(t.findings, eq(t.findings.findingId, t.findingAssessments.findingId))
      .where(eq(t.findings.projectId, projectId))
      .orderBy(asc(t.findingAssessments.assessedAt), asc(t.findingAssessments.assessmentId))
      .all();
    for (const row of assessments) {
      const a = FindingAssessment.parse(row.data);
      result.set(a.findingId, { ...result.get(a.findingId), assessment: a });
    }
    const occurrences = this.db
      .select({ data: t.findingOccurrences.data })
      .from(t.findingOccurrences)
      .innerJoin(t.findings, eq(t.findings.findingId, t.findingOccurrences.findingId))
      .where(eq(t.findings.projectId, projectId))
      .orderBy(asc(t.findingOccurrences.occurrenceId))
      .all();
    for (const row of occurrences) {
      const o = FindingOccurrence.parse(row.data);
      result.set(o.findingId, { ...result.get(o.findingId), occurrence: o });
    }
    return result;
  }

  async listMatchEvents(scanId: string): Promise<FindingMatchEvent[]> {
    return this.db
      .select({ data: t.findingMatchEvents.data })
      .from(t.findingMatchEvents)
      .where(eq(t.findingMatchEvents.scanId, scanId))
      .orderBy(asc(t.findingMatchEvents.eventId))
      .all()
      .map((r) => FindingMatchEvent.parse(r.data));
  }

  async saveDisposition(disposition: Disposition): Promise<void> {
    this.db
      .insert(t.findingDispositions)
      .values({
        dispositionId: disposition.dispositionId,
        findingId: disposition.findingId,
        kind: disposition.kind,
        decidedAt: disposition.decidedAt,
        data: disposition,
      })
      .run();
  }

  async listDispositions(projectId: string): Promise<Disposition[]> {
    return this.db
      .select({ data: t.findingDispositions.data })
      .from(t.findingDispositions)
      .innerJoin(t.findings, eq(t.findings.findingId, t.findingDispositions.findingId))
      .where(eq(t.findings.projectId, projectId))
      .orderBy(asc(t.findingDispositions.decidedAt))
      .all()
      .map((r) => Disposition.parse(r.data));
  }

  async activateBaseline(baseline: BaselineRecord, expectedCurrentId?: string): Promise<void> {
    this.db.transaction((tx) => {
      const current = tx
        .select()
        .from(t.baselines)
        .where(
          and(
            eq(t.baselines.projectId, baseline.projectId),
            eq(t.baselines.scopeType, baseline.scopeType),
            eq(t.baselines.scopeRef, baseline.scopeRef),
            isNull(t.baselines.deactivatedAt),
          ),
        )
        .get();
      if (current?.baselineId !== expectedCurrentId) {
        throw new Error(`baseline for ${baseline.scopeType} ${baseline.scopeRef} changed concurrently; retry`);
      }
      if (current) {
        tx.update(t.baselines)
          .set({ deactivatedAt: baseline.activatedAt })
          .where(eq(t.baselines.baselineId, current.baselineId))
          .run();
      }
      tx.insert(t.baselines)
        .values({
          baselineId: baseline.baselineId,
          projectId: baseline.projectId,
          scopeType: baseline.scopeType,
          scopeRef: baseline.scopeRef,
          scanId: baseline.scanId,
          reason: baseline.reason,
          activatedAt: baseline.activatedAt,
        })
        .run();
    });
  }

  async activeBaseline(
    projectId: string,
    scopeType: BaselineRecord['scopeType'],
    scopeRef: string,
  ): Promise<BaselineRecord | undefined> {
    const row = this.db
      .select()
      .from(t.baselines)
      .where(
        and(
          eq(t.baselines.projectId, projectId),
          eq(t.baselines.scopeType, scopeType),
          eq(t.baselines.scopeRef, scopeRef),
          isNull(t.baselines.deactivatedAt),
        ),
      )
      .get();
    return row ? toBaseline(row) : undefined;
  }

  async listBaselines(projectId: string): Promise<BaselineRecord[]> {
    return this.db
      .select()
      .from(t.baselines)
      .where(eq(t.baselines.projectId, projectId))
      .orderBy(desc(t.baselines.activatedAt))
      .all()
      .map(toBaseline);
  }

  async saveAgentRun(run: AgentRunRecord): Promise<void> {
    const values = {
      agentRunId: run.agentRunId,
      role: run.role,
      scanId: run.scanId ?? null,
      findingId: run.findingId ?? null,
      status: run.status,
      startedAt: run.startedAt,
      data: run,
    };
    const { agentRunId: _id, ...update } = values;
    this.db
      .insert(t.agentRuns)
      .values(values)
      .onConflictDoUpdate({ target: t.agentRuns.agentRunId, set: update })
      .run();
  }

  async listAgentRuns(filter: { scanId?: string; findingId?: string }): Promise<AgentRunRecord[]> {
    return this.db
      .select({ data: t.agentRuns.data })
      .from(t.agentRuns)
      .where(
        and(
          filter.scanId ? eq(t.agentRuns.scanId, filter.scanId) : undefined,
          filter.findingId ? eq(t.agentRuns.findingId, filter.findingId) : undefined,
        ),
      )
      .orderBy(asc(t.agentRuns.startedAt), asc(t.agentRuns.agentRunId))
      .all()
      .map((r) => AgentRunRecord.parse(r.data));
  }
}

function toBaseline(row: typeof t.baselines.$inferSelect): BaselineRecord {
  return {
    baselineId: row.baselineId,
    projectId: row.projectId,
    scopeType: row.scopeType as BaselineRecord['scopeType'],
    scopeRef: row.scopeRef,
    scanId: row.scanId,
    reason: row.reason,
    activatedAt: row.activatedAt,
    ...(row.deactivatedAt ? { deactivatedAt: row.deactivatedAt } : {}),
  };
}

function* chunks<T>(items: readonly T[]): Generator<T[]> {
  for (let i = 0; i < items.length; i += CHUNK) yield items.slice(i, i + CHUNK);
}

/** SQL NULL columns become absent optional properties in the domain objects. */
function stripNulls<T extends Record<string, unknown>>(row: T): { [K in keyof T]: Exclude<T[K], null> } {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(row)) if (value !== null) out[key] = value;
  return out as { [K in keyof T]: Exclude<T[K], null> };
}
