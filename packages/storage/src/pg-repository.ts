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
import pg from 'pg';

const SCHEMA_NAME = /^[a-z_][a-z0-9_]{0,62}$/;

/**
 * PostgreSQL system of record (ADR-019, ADR-037). Each project lives in its own schema, which keeps
 * the single-project semantics of the SQLite state database and isolates projects (tenants) at the
 * schema level. Rows keep the validated domain object as JSONB plus the columns used for lookups.
 */
const DDL = (s: string) => `
CREATE SCHEMA IF NOT EXISTS ${s};
CREATE TABLE IF NOT EXISTS ${s}.projects (project_id text PRIMARY KEY, created_at text NOT NULL, data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS ${s}.repositories (repository_id text PRIMARY KEY, project_id text NOT NULL REFERENCES ${s}.projects, created_at text NOT NULL, data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS ${s}.snapshots (snapshot_id text PRIMARY KEY, data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS ${s}.scans (scan_id text PRIMARY KEY, project_id text NOT NULL REFERENCES ${s}.projects, status text NOT NULL, requested_at text NOT NULL, data jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS scans_project ON ${s}.scans (project_id, requested_at);
CREATE TABLE IF NOT EXISTS ${s}.tasks (task_id text PRIMARY KEY, scan_id text NOT NULL REFERENCES ${s}.scans, idempotency_key text NOT NULL, status text NOT NULL, completed_at text, data jsonb NOT NULL, UNIQUE (scan_id, idempotency_key));
CREATE INDEX IF NOT EXISTS tasks_key ON ${s}.tasks (idempotency_key, status);
CREATE TABLE IF NOT EXISTS ${s}.candidates (candidate_id text PRIMARY KEY, scan_id text NOT NULL REFERENCES ${s}.scans, data jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS candidates_scan ON ${s}.candidates (scan_id);
CREATE TABLE IF NOT EXISTS ${s}.evidence (evidence_id text PRIMARY KEY, data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS ${s}.findings (finding_id text PRIMARY KEY, project_id text NOT NULL REFERENCES ${s}.projects, seq integer NOT NULL, data jsonb NOT NULL, UNIQUE (project_id, seq));
CREATE TABLE IF NOT EXISTS ${s}.fingerprints (project_id text NOT NULL, fingerprint text NOT NULL, finding_id text NOT NULL REFERENCES ${s}.findings, algorithm text NOT NULL, created_at text NOT NULL, PRIMARY KEY (project_id, fingerprint));
CREATE TABLE IF NOT EXISTS ${s}.occurrences (occurrence_id text PRIMARY KEY, finding_id text NOT NULL REFERENCES ${s}.findings, scan_id text NOT NULL REFERENCES ${s}.scans, data jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS occurrences_scan ON ${s}.occurrences (scan_id);
CREATE INDEX IF NOT EXISTS occurrences_finding ON ${s}.occurrences (finding_id);
CREATE TABLE IF NOT EXISTS ${s}.assessments (assessment_id text PRIMARY KEY, finding_id text NOT NULL REFERENCES ${s}.findings, scan_id text NOT NULL REFERENCES ${s}.scans, assessed_at text NOT NULL, data jsonb NOT NULL, UNIQUE (scan_id, finding_id));
CREATE INDEX IF NOT EXISTS assessments_finding ON ${s}.assessments (finding_id, assessed_at);
CREATE TABLE IF NOT EXISTS ${s}.dispositions (disposition_id text PRIMARY KEY, finding_id text NOT NULL REFERENCES ${s}.findings, decided_at text NOT NULL, data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS ${s}.match_events (event_id text PRIMARY KEY, scan_id text NOT NULL REFERENCES ${s}.scans, data jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS match_events_scan ON ${s}.match_events (scan_id);
CREATE TABLE IF NOT EXISTS ${s}.baselines (baseline_id text PRIMARY KEY, project_id text NOT NULL REFERENCES ${s}.projects, scope_type text NOT NULL, scope_ref text NOT NULL, scan_id text NOT NULL REFERENCES ${s}.scans, reason text NOT NULL, activated_at text NOT NULL, deactivated_at text);
CREATE INDEX IF NOT EXISTS baselines_scope ON ${s}.baselines (project_id, scope_type, scope_ref);
CREATE TABLE IF NOT EXISTS ${s}.agent_runs (agent_run_id text PRIMARY KEY, scan_id text, finding_id text, started_at text NOT NULL, data jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS agent_runs_scan ON ${s}.agent_runs (scan_id);
CREATE INDEX IF NOT EXISTS agent_runs_finding ON ${s}.agent_runs (finding_id, started_at);
`;

type Queryable = Pick<pg.PoolClient, 'query'>;

export class PgScanRepository implements ScanRepository {
  private readonly ready: Promise<void>;
  private readonly s: string;

  private constructor(
    private readonly pool: pg.Pool,
    schema: string,
    private readonly ownsPool: boolean,
  ) {
    if (!SCHEMA_NAME.test(schema)) throw new Error(`invalid schema name ${schema}`);
    this.s = `"${schema}"`;
    // Concurrent openers of a new schema serialise on an advisory lock.
    this.ready = this.tx(async (c) => {
      await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [schema]);
      await c.query(DDL(this.s));
    });
  }

  /** Opens (and creates on first use) the repository in `schema`; pass a shared pool to reuse connections. */
  static open(input: { schema: string; pool?: pg.Pool; connectionString?: string }): PgScanRepository {
    const pool = input.pool ?? new pg.Pool({ connectionString: input.connectionString, max: 4 });
    return new PgScanRepository(pool, input.schema, !input.pool);
  }

  /** Schema name for a project key (lower-case letters, digits, underscore). */
  static schemaFor(key: string): string {
    return `spx_${key.toLowerCase().replace(/[^a-z0-9_]/g, '_')}`.slice(0, 63);
  }

  async close(): Promise<void> {
    await this.ready.catch(() => {});
    if (this.ownsPool) await this.pool.end();
  }

  private async tx<T>(fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const out = await fn(client);
      await client.query('COMMIT');
      return out;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  private async q<R extends pg.QueryResultRow = { data: unknown }>(
    sql: string,
    params: unknown[] = [],
    c: Queryable = this.pool,
  ): Promise<R[]> {
    await this.ready;
    return (await c.query<R>(sql, params)).rows;
  }

  private data<T>(rows: Array<{ data: unknown }>, parse: (v: unknown) => T): T[] {
    return rows.map((r) => parse(r.data));
  }

  async ensureProject(input: {
    name: string;
    rootPath: string;
  }): Promise<{ project: ProjectRecord; repository: RepositoryRecord }> {
    await this.ready;
    return this.tx(async (c) => {
      await c.query(`LOCK TABLE ${this.s}.projects IN EXCLUSIVE MODE`);
      const existing = await this.projectWith(c);
      if (existing) return existing;
      const createdAt = new Date().toISOString();
      const project: ProjectRecord = { projectId: newId('prj'), name: input.name, createdAt };
      const repository: RepositoryRecord = {
        repositoryId: newId('repo'),
        projectId: project.projectId,
        rootPath: input.rootPath,
        createdAt,
      };
      await c.query(`INSERT INTO ${this.s}.projects VALUES ($1, $2, $3)`, [project.projectId, createdAt, project]);
      await c.query(`INSERT INTO ${this.s}.repositories VALUES ($1, $2, $3, $4)`, [
        repository.repositoryId,
        project.projectId,
        createdAt,
        repository,
      ]);
      return { project, repository };
    });
  }

  async getProject(): Promise<{ project: ProjectRecord; repository: RepositoryRecord } | undefined> {
    await this.ready;
    return this.projectWith(this.pool);
  }

  private async projectWith(
    c: Queryable,
  ): Promise<{ project: ProjectRecord; repository: RepositoryRecord } | undefined> {
    const project = (
      await c.query<{ data: ProjectRecord }>(`SELECT data FROM ${this.s}.projects ORDER BY created_at LIMIT 1`)
    ).rows[0]?.data;
    if (!project) return undefined;
    const repository = (
      await c.query<{ data: RepositoryRecord }>(
        `SELECT data FROM ${this.s}.repositories WHERE project_id = $1 ORDER BY created_at LIMIT 1`,
        [project.projectId],
      )
    ).rows[0]?.data;
    return repository ? { project, repository } : undefined;
  }

  async saveSnapshot(snapshot: SourceSnapshot): Promise<void> {
    await this.q(`INSERT INTO ${this.s}.snapshots VALUES ($1, $2) ON CONFLICT DO NOTHING`, [
      snapshot.snapshotId,
      snapshot,
    ]);
  }

  async getSnapshot(snapshotId: string): Promise<SourceSnapshot | undefined> {
    return this.data(await this.q(`SELECT data FROM ${this.s}.snapshots WHERE snapshot_id = $1`, [snapshotId]), (d) =>
      SourceSnapshot.parse(d),
    )[0];
  }

  async createScan(scan: ScanRun): Promise<void> {
    await this.q(`INSERT INTO ${this.s}.scans VALUES ($1, $2, $3, $4, $5)`, [
      scan.scanId,
      scan.projectId,
      scan.status,
      scan.requestedAt,
      scan,
    ]);
  }

  async updateScan(
    scanId: string,
    patch: Partial<Pick<ScanRun, 'status' | 'startedAt' | 'completedAt' | 'summary' | 'error'>>,
  ): Promise<void> {
    await this.q(
      `UPDATE ${this.s}.scans SET data = data || $2::jsonb, status = COALESCE($3, status) WHERE scan_id = $1`,
      [scanId, JSON.stringify(patch), patch.status ?? null],
    );
  }

  async getScan(scanId: string): Promise<ScanRun | undefined> {
    return this.data(await this.q(`SELECT data FROM ${this.s}.scans WHERE scan_id = $1`, [scanId]), (d) =>
      ScanRun.parse(d),
    )[0];
  }

  async listScans(projectId: string, limit = 50): Promise<ScanRun[]> {
    return this.data(
      await this.q(
        `SELECT data FROM ${this.s}.scans WHERE project_id = $1 ORDER BY requested_at DESC, scan_id DESC LIMIT $2`,
        [projectId, limit],
      ),
      (d) => ScanRun.parse(d),
    );
  }

  async latestScan(
    projectId: string,
    statuses: readonly ScanStatus[],
    excludeScanId?: string,
  ): Promise<ScanRun | undefined> {
    return this.data(
      await this.q(
        `SELECT data FROM ${this.s}.scans WHERE project_id = $1 AND status = ANY($2) AND ($3::text IS NULL OR scan_id <> $3)
         ORDER BY requested_at DESC, scan_id DESC LIMIT 1`,
        [projectId, [...statuses], excludeScanId ?? null],
      ),
      (d) => ScanRun.parse(d),
    )[0];
  }

  async upsertTask(task: ScanTask): Promise<void> {
    await this.q(
      `INSERT INTO ${this.s}.tasks VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (task_id) DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key, status = EXCLUDED.status, completed_at = EXCLUDED.completed_at, data = EXCLUDED.data`,
      [task.taskId, task.scanId, task.idempotencyKey, task.status, task.completedAt ?? null, task],
    );
  }

  async listTasks(scanId: string): Promise<ScanTask[]> {
    return this.data(
      await this.q(`SELECT data FROM ${this.s}.tasks WHERE scan_id = $1 ORDER BY task_id`, [scanId]),
      (d) => ScanTask.parse(d),
    );
  }

  async findReusableTask(idempotencyKey: string): Promise<ScanTask | undefined> {
    return this.data(
      await this.q(
        `SELECT data FROM ${this.s}.tasks WHERE idempotency_key = $1 AND status IN ('SUCCEEDED', 'PARTIAL') ORDER BY completed_at DESC NULLS LAST LIMIT 1`,
        [idempotencyKey],
      ),
      (d) => ScanTask.parse(d),
    )[0];
  }

  async saveCandidates(candidates: FindingCandidate[]): Promise<void> {
    if (candidates.length === 0) return;
    await this.q(
      `INSERT INTO ${this.s}.candidates SELECT * FROM jsonb_to_recordset($1::jsonb) AS x(candidate_id text, scan_id text, data jsonb) ON CONFLICT DO NOTHING`,
      [JSON.stringify(candidates.map((c) => ({ candidate_id: c.candidateId, scan_id: c.scanId, data: c })))],
    );
  }

  async listCandidates(scanId: string): Promise<FindingCandidate[]> {
    return this.data(
      await this.q(`SELECT data FROM ${this.s}.candidates WHERE scan_id = $1 ORDER BY candidate_id`, [scanId]),
      (d) => FindingCandidate.parse(d),
    );
  }

  async saveEvidence(evidence: Evidence[]): Promise<void> {
    if (evidence.length === 0) return;
    await this.q(
      `INSERT INTO ${this.s}.evidence SELECT * FROM jsonb_to_recordset($1::jsonb) AS x(evidence_id text, data jsonb) ON CONFLICT DO NOTHING`,
      [JSON.stringify(evidence.map((e) => ({ evidence_id: e.evidenceId, data: e })))],
    );
  }

  async getEvidence(ids: readonly string[]): Promise<Evidence[]> {
    if (ids.length === 0) return [];
    const rows = this.data(
      await this.q(`SELECT data FROM ${this.s}.evidence WHERE evidence_id = ANY($1)`, [[...ids]]),
      (d) => Evidence.parse(d),
    );
    const byId = new Map(rows.map((e) => [e.evidenceId, e]));
    return ids.map((id) => byId.get(id)).filter((e): e is Evidence => e !== undefined);
  }

  async nextFindingSeq(projectId: string): Promise<number> {
    const rows = await this.q<{ v: number | null }>(
      `SELECT MAX(seq) AS v FROM ${this.s}.findings WHERE project_id = $1`,
      [projectId],
    );
    return (rows[0]?.v ?? 0) + 1;
  }

  async listFindings(projectId: string): Promise<Finding[]> {
    return this.data(
      await this.q(`SELECT data FROM ${this.s}.findings WHERE project_id = $1 ORDER BY seq`, [projectId]),
      (d) => Finding.parse(d),
    );
  }

  async getFinding(findingId: string): Promise<Finding | undefined> {
    return this.data(await this.q(`SELECT data FROM ${this.s}.findings WHERE finding_id = $1`, [findingId]), (d) =>
      Finding.parse(d),
    )[0];
  }

  async fingerprintIndex(projectId: string): Promise<Map<string, string>> {
    const rows = await this.q<{ fingerprint: string; finding_id: string }>(
      `SELECT fingerprint, finding_id FROM ${this.s}.fingerprints WHERE project_id = $1`,
      [projectId],
    );
    return new Map(rows.map((r) => [r.fingerprint, r.finding_id]));
  }

  async commitReconciliation(scanId: string, commit: ReconciliationCommit): Promise<void> {
    const scan = await this.getScan(scanId);
    if (!scan) throw new Error(`scan ${scanId} not found`);
    const now = new Date().toISOString();
    await this.tx(async (c) => {
      for (const f of commit.newFindings) {
        await c.query(`INSERT INTO ${this.s}.findings VALUES ($1, $2, $3, $4)`, [f.findingId, f.projectId, f.seq, f]);
        await c.query(`INSERT INTO ${this.s}.fingerprints VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`, [
          f.projectId,
          f.canonicalFingerprint,
          f.findingId,
          f.fingerprintAlgorithm,
          now,
        ]);
      }
      for (const a of commit.fingerprintAliases) {
        await c.query(`INSERT INTO ${this.s}.fingerprints VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`, [
          scan.projectId,
          a.fingerprint,
          a.findingId,
          a.algorithm,
          now,
        ]);
      }
      if (commit.occurrences.length) {
        await c.query(
          `INSERT INTO ${this.s}.occurrences SELECT * FROM jsonb_to_recordset($1::jsonb) AS x(occurrence_id text, finding_id text, scan_id text, data jsonb)`,
          [
            JSON.stringify(
              commit.occurrences.map((o) => ({
                occurrence_id: o.occurrenceId,
                finding_id: o.findingId,
                scan_id: o.scanId,
                data: o,
              })),
            ),
          ],
        );
      }
      if (commit.assessments.length) {
        await c.query(
          `INSERT INTO ${this.s}.assessments SELECT * FROM jsonb_to_recordset($1::jsonb) AS x(assessment_id text, finding_id text, scan_id text, assessed_at text, data jsonb)`,
          [
            JSON.stringify(
              commit.assessments.map((a) => ({
                assessment_id: a.assessmentId,
                finding_id: a.findingId,
                scan_id: a.scanId,
                assessed_at: a.assessedAt,
                data: a,
              })),
            ),
          ],
        );
      }
      if (commit.matchEvents.length) {
        await c.query(
          `INSERT INTO ${this.s}.match_events SELECT * FROM jsonb_to_recordset($1::jsonb) AS x(event_id text, scan_id text, data jsonb)`,
          [JSON.stringify(commit.matchEvents.map((e) => ({ event_id: e.eventId, scan_id: e.scanId, data: e })))],
        );
      }
    });
  }

  async listOccurrences(scanId: string): Promise<FindingOccurrence[]> {
    return this.data(
      await this.q(`SELECT data FROM ${this.s}.occurrences WHERE scan_id = $1 ORDER BY occurrence_id`, [scanId]),
      (d) => FindingOccurrence.parse(d),
    );
  }

  async occurrencesForFinding(findingId: string): Promise<FindingOccurrence[]> {
    return this.data(
      await this.q(`SELECT data FROM ${this.s}.occurrences WHERE finding_id = $1 ORDER BY occurrence_id`, [findingId]),
      (d) => FindingOccurrence.parse(d),
    );
  }

  async listAssessments(scanId: string): Promise<FindingAssessment[]> {
    return this.data(
      await this.q(`SELECT data FROM ${this.s}.assessments WHERE scan_id = $1 ORDER BY finding_id`, [scanId]),
      (d) => FindingAssessment.parse(d),
    );
  }

  async assessmentsForFinding(findingId: string): Promise<FindingAssessment[]> {
    return this.data(
      await this.q(`SELECT data FROM ${this.s}.assessments WHERE finding_id = $1 ORDER BY assessed_at, assessment_id`, [
        findingId,
      ]),
      (d) => FindingAssessment.parse(d),
    );
  }

  async latestByFinding(
    projectId: string,
  ): Promise<Map<string, { assessment?: FindingAssessment; occurrence?: FindingOccurrence }>> {
    const result = new Map<string, { assessment?: FindingAssessment; occurrence?: FindingOccurrence }>();
    const assessments = await this.q(
      `SELECT a.data FROM ${this.s}.assessments a JOIN ${this.s}.findings f ON f.finding_id = a.finding_id WHERE f.project_id = $1 ORDER BY a.assessed_at, a.assessment_id`,
      [projectId],
    );
    for (const a of this.data(assessments, (d) => FindingAssessment.parse(d)))
      result.set(a.findingId, { ...result.get(a.findingId), assessment: a });
    const occurrences = await this.q(
      `SELECT o.data FROM ${this.s}.occurrences o JOIN ${this.s}.findings f ON f.finding_id = o.finding_id WHERE f.project_id = $1 ORDER BY o.occurrence_id`,
      [projectId],
    );
    for (const o of this.data(occurrences, (d) => FindingOccurrence.parse(d)))
      result.set(o.findingId, { ...result.get(o.findingId), occurrence: o });
    return result;
  }

  async listMatchEvents(scanId: string): Promise<FindingMatchEvent[]> {
    return this.data(
      await this.q(`SELECT data FROM ${this.s}.match_events WHERE scan_id = $1 ORDER BY event_id`, [scanId]),
      (d) => FindingMatchEvent.parse(d),
    );
  }

  async saveDisposition(disposition: Disposition): Promise<void> {
    await this.q(`INSERT INTO ${this.s}.dispositions VALUES ($1, $2, $3, $4)`, [
      disposition.dispositionId,
      disposition.findingId,
      disposition.decidedAt,
      disposition,
    ]);
  }

  async listDispositions(projectId: string): Promise<Disposition[]> {
    return this.data(
      await this.q(
        `SELECT d.data FROM ${this.s}.dispositions d JOIN ${this.s}.findings f ON f.finding_id = d.finding_id WHERE f.project_id = $1 ORDER BY d.decided_at`,
        [projectId],
      ),
      (d) => Disposition.parse(d),
    );
  }

  async activateBaseline(baseline: BaselineRecord, expectedCurrentId?: string): Promise<void> {
    await this.ready;
    await this.tx(async (c) => {
      const current = (
        await c.query<{ baseline_id: string }>(
          `SELECT baseline_id FROM ${this.s}.baselines WHERE project_id = $1 AND scope_type = $2 AND scope_ref = $3 AND deactivated_at IS NULL FOR UPDATE`,
          [baseline.projectId, baseline.scopeType, baseline.scopeRef],
        )
      ).rows[0];
      if (current?.baseline_id !== expectedCurrentId) {
        throw new Error(`baseline for ${baseline.scopeType} ${baseline.scopeRef} changed concurrently; retry`);
      }
      if (current)
        await c.query(`UPDATE ${this.s}.baselines SET deactivated_at = $2 WHERE baseline_id = $1`, [
          current.baseline_id,
          baseline.activatedAt,
        ]);
      await c.query(`INSERT INTO ${this.s}.baselines VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)`, [
        baseline.baselineId,
        baseline.projectId,
        baseline.scopeType,
        baseline.scopeRef,
        baseline.scanId,
        baseline.reason,
        baseline.activatedAt,
      ]);
    });
  }

  async activeBaseline(
    projectId: string,
    scopeType: BaselineRecord['scopeType'],
    scopeRef: string,
  ): Promise<BaselineRecord | undefined> {
    const rows = await this.q<BaselineRow>(
      `SELECT * FROM ${this.s}.baselines WHERE project_id = $1 AND scope_type = $2 AND scope_ref = $3 AND deactivated_at IS NULL`,
      [projectId, scopeType, scopeRef],
    );
    return rows[0] ? toBaseline(rows[0]) : undefined;
  }

  async listBaselines(projectId: string): Promise<BaselineRecord[]> {
    return (
      await this.q<BaselineRow>(`SELECT * FROM ${this.s}.baselines WHERE project_id = $1 ORDER BY activated_at DESC`, [
        projectId,
      ])
    ).map(toBaseline);
  }

  async saveAgentRun(run: AgentRunRecord): Promise<void> {
    await this.q(
      `INSERT INTO ${this.s}.agent_runs VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (agent_run_id) DO UPDATE SET scan_id = EXCLUDED.scan_id, finding_id = EXCLUDED.finding_id, started_at = EXCLUDED.started_at, data = EXCLUDED.data`,
      [run.agentRunId, run.scanId ?? null, run.findingId ?? null, run.startedAt, run],
    );
  }

  async listAgentRuns(filter: { scanId?: string; findingId?: string }): Promise<AgentRunRecord[]> {
    return this.data(
      await this.q(
        `SELECT data FROM ${this.s}.agent_runs WHERE ($1::text IS NULL OR scan_id = $1) AND ($2::text IS NULL OR finding_id = $2) ORDER BY started_at, agent_run_id`,
        [filter.scanId ?? null, filter.findingId ?? null],
      ),
      (d) => AgentRunRecord.parse(d),
    );
  }
}

interface BaselineRow {
  baseline_id: string;
  project_id: string;
  scope_type: string;
  scope_ref: string;
  scan_id: string;
  reason: string;
  activated_at: string;
  deactivated_at: string | null;
}

function toBaseline(row: BaselineRow): BaselineRecord {
  return {
    baselineId: row.baseline_id,
    projectId: row.project_id,
    scopeType: row.scope_type as BaselineRecord['scopeType'],
    scopeRef: row.scope_ref,
    scanId: row.scan_id,
    reason: row.reason,
    activatedAt: row.activated_at,
    ...(row.deactivated_at ? { deactivatedAt: row.deactivated_at } : {}),
  };
}
