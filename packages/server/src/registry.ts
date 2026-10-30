import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { newId } from '@spinxsca/core';
import Database from 'better-sqlite3';

/** Server registry (ADR-034): projects, API tokens, UI sessions, jobs and the audit log. */
const SCHEMA = `
CREATE TABLE IF NOT EXISTS projects (
  project_id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  source_kind TEXT NOT NULL,
  location TEXT NOT NULL,
  default_branch TEXT NOT NULL,
  webhook_secret TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
  token_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  session_hash TEXT PRIMARY KEY,
  token_id TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
  job_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  project_id TEXT,
  payload TEXT NOT NULL,
  status TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL,
  run_after TEXT NOT NULL,
  lease_until TEXT,
  idempotency_key TEXT UNIQUE,
  result TEXT,
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_ready ON jobs (status, run_after);
CREATE TABLE IF NOT EXISTS workers (
  worker_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  pools TEXT NOT NULL,
  capabilities TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen_at TEXT,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS worker_provisioning (
  token_hash TEXT PRIMARY KEY,
  pools TEXT NOT NULL,
  created_by TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT
);
`;

export type Role = 'admin' | 'member' | 'viewer';
export const ROLE_RANK: Record<Role, number> = { viewer: 0, member: 1, admin: 2 };

export interface ProjectEntry {
  projectId: string;
  name: string;
  source: { kind: 'git'; url: string } | { kind: 'local'; path: string };
  defaultBranch: string;
  /** Workers that may run this project's scans (on-prem projects use their own pool). */
  workerPool: string;
  webhookSecret: string;
  createdAt: string;
}

export interface TokenEntry {
  tokenId: string;
  name: string;
  role: Role;
  createdAt: string;
  lastUsedAt?: string;
  revokedAt?: string;
}

export type JobKind = 'SCAN' | 'REASSESS' | 'KB_SYNC';
export type JobStatus = 'QUEUED' | 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'CANCELLED';

export interface JobEntry {
  jobId: string;
  kind: JobKind;
  projectId?: string;
  payload: Record<string, unknown>;
  status: JobStatus;
  attempts: number;
  maxAttempts: number;
  runAfter: string;
  pool: string;
  /** Incremented on every claim; results are accepted only with the current value (fencing token). */
  fencing: number;
  workerId?: string;
  leaseUntil?: string;
  idempotencyKey?: string;
  result?: Record<string, unknown>;
  error?: string;
  createdAt: string;
  updatedAt: string;
}

export interface WorkerEntry {
  workerId: string;
  name: string;
  pools: string[];
  capabilities: Record<string, unknown>;
  createdAt: string;
  lastSeenAt?: string;
  revokedAt?: string;
}

/** Jobs that remote workers may run; KB_SYNC stays on the control plane. */
export const REMOTE_JOB_KINDS: readonly JobKind[] = ['SCAN', 'REASSESS'];

export interface AuditEntry {
  seq: number;
  at: string;
  actor: string;
  action: string;
  target?: string;
  detail?: Record<string, unknown>;
}

const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const TOKEN_PREFIX = 'spx_';
const WORKER_PREFIX = 'spxw_';
const PROVISION_PREFIX = 'spxp_';
/** Pool of jobs only the control plane runs (knowledge base refresh). */
export const CONTROL_POOL = 'control';
export const LOCAL_WORKER = 'local';

export class Registry {
  readonly db: Database.Database;
  /** Called for every newly created job (external orchestrators such as Temporal start work here). */
  onEnqueued: ((job: JobEntry) => void) | undefined;

  private constructor(readonly dataDir: string) {
    mkdirSync(dataDir, { recursive: true });
    this.db = new Database(join(dataDir, 'server.db'));
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('busy_timeout = 5000');
    this.db.exec(SCHEMA);
    this.addColumn('jobs', 'fencing', 'INTEGER NOT NULL DEFAULT 0');
    this.addColumn('jobs', 'worker_id', 'TEXT');
    this.addColumn('jobs', 'pool', "TEXT NOT NULL DEFAULT 'default'");
    this.addColumn('projects', 'worker_pool', "TEXT NOT NULL DEFAULT 'default'");
    this.addColumn('worker_provisioning', 'max_uses', 'INTEGER NOT NULL DEFAULT 1');
    this.addColumn('worker_provisioning', 'uses', 'INTEGER NOT NULL DEFAULT 0');
  }

  private addColumn(table: string, column: string, definition: string): void {
    const columns = this.db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
    if (!columns.some((c) => c.name === column))
      this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }

  static open(dataDir: string): Registry {
    return new Registry(dataDir);
  }

  close(): void {
    this.db.close();
  }

  // Projects ---------------------------------------------------------------

  createProject(
    input: { name: string; source: ProjectEntry['source']; defaultBranch: string; workerPool?: string },
    now: Date,
  ): ProjectEntry {
    const project: ProjectEntry = {
      projectId: newId('srvprj'),
      name: input.name,
      source: input.source,
      defaultBranch: input.defaultBranch,
      workerPool: input.workerPool ?? 'default',
      webhookSecret: randomBytes(24).toString('base64url'),
      createdAt: now.toISOString(),
    };
    this.db
      .prepare(
        'INSERT INTO projects (project_id, name, source_kind, location, default_branch, worker_pool, webhook_secret, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      )
      .run(
        project.projectId,
        project.name,
        project.source.kind,
        project.source.kind === 'git' ? project.source.url : project.source.path,
        project.defaultBranch,
        project.workerPool,
        project.webhookSecret,
        project.createdAt,
      );
    return project;
  }

  project(projectId: string): ProjectEntry | undefined {
    const row = this.db.prepare('SELECT * FROM projects WHERE project_id = ?').get(projectId) as ProjectRow | undefined;
    return row ? toProject(row) : undefined;
  }

  projects(): ProjectEntry[] {
    return (this.db.prepare('SELECT * FROM projects ORDER BY name').all() as ProjectRow[]).map(toProject);
  }

  // Tokens and sessions ------------------------------------------------------

  /** Creates an API token; the plaintext is returned once and only its hash is stored. */
  createToken(name: string, role: Role, now: Date): { token: string; entry: TokenEntry } {
    const token = `${TOKEN_PREFIX}${randomBytes(32).toString('base64url')}`;
    const entry: TokenEntry = { tokenId: newId('tok'), name, role, createdAt: now.toISOString() };
    this.db
      .prepare('INSERT INTO tokens (token_id, name, role, token_hash, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(entry.tokenId, name, role, hash(token), entry.createdAt);
    return { token, entry };
  }

  authenticate(token: string, now: Date): TokenEntry | undefined {
    if (!token.startsWith(TOKEN_PREFIX)) return undefined;
    const row = this.db.prepare('SELECT * FROM tokens WHERE token_hash = ? AND revoked_at IS NULL').get(hash(token)) as
      | TokenRow
      | undefined;
    if (!row) return undefined;
    this.db.prepare('UPDATE tokens SET last_used_at = ? WHERE token_id = ?').run(now.toISOString(), row.token_id);
    return toToken(row);
  }

  tokens(): TokenEntry[] {
    return (this.db.prepare('SELECT * FROM tokens ORDER BY created_at').all() as TokenRow[]).map(toToken);
  }

  revokeToken(tokenId: string, now: Date): boolean {
    return (
      this.db
        .prepare('UPDATE tokens SET revoked_at = ? WHERE token_id = ? AND revoked_at IS NULL')
        .run(now.toISOString(), tokenId).changes > 0
    );
  }

  createSession(tokenId: string, now: Date, ttlHours = 12): string {
    const session = randomBytes(32).toString('base64url');
    this.db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now.toISOString());
    this.db
      .prepare('INSERT INTO sessions (session_hash, token_id, expires_at) VALUES (?, ?, ?)')
      .run(hash(session), tokenId, new Date(now.getTime() + ttlHours * 3_600_000).toISOString());
    return session;
  }

  sessionToken(session: string, now: Date): TokenEntry | undefined {
    const row = this.db
      .prepare(
        'SELECT t.* FROM sessions s JOIN tokens t ON t.token_id = s.token_id WHERE s.session_hash = ? AND s.expires_at > ? AND t.revoked_at IS NULL',
      )
      .get(hash(session), now.toISOString()) as TokenRow | undefined;
    return row ? toToken(row) : undefined;
  }

  deleteSession(session: string): void {
    this.db.prepare('DELETE FROM sessions WHERE session_hash = ?').run(hash(session));
  }

  // Jobs ---------------------------------------------------------------------

  /**
   * Enqueues a job. A job with the same idempotency key is returned instead of duplicated, so a
   * webhook redelivery or a repeated schedule tick does not run the work twice. Project jobs go to the
   * project's worker pool; knowledge base refreshes stay on the control plane.
   */
  enqueue(
    input: {
      kind: JobKind;
      projectId?: string;
      payload: Record<string, unknown>;
      idempotencyKey?: string;
      maxAttempts?: number;
      runAfter?: Date;
      pool?: string;
    },
    now: Date,
  ): { job: JobEntry; created: boolean } {
    if (input.idempotencyKey) {
      const existing = this.jobByKey(input.idempotencyKey);
      if (existing) return { job: existing, created: false };
    }
    const at = now.toISOString();
    const pool =
      input.pool ??
      (input.kind === 'KB_SYNC'
        ? CONTROL_POOL
        : (input.projectId && this.project(input.projectId)?.workerPool) || 'default');
    const job: JobEntry = {
      jobId: newId('job'),
      kind: input.kind,
      ...(input.projectId ? { projectId: input.projectId } : {}),
      payload: input.payload,
      status: 'QUEUED',
      attempts: 0,
      maxAttempts: input.maxAttempts ?? 3,
      runAfter: (input.runAfter ?? now).toISOString(),
      pool,
      fencing: 0,
      ...(input.idempotencyKey ? { idempotencyKey: input.idempotencyKey } : {}),
      createdAt: at,
      updatedAt: at,
    };
    this.db
      .prepare(
        `INSERT INTO jobs (job_id, kind, project_id, payload, status, attempts, max_attempts, run_after, pool, idempotency_key, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'QUEUED', 0, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        job.jobId,
        job.kind,
        job.projectId ?? null,
        JSON.stringify(job.payload),
        job.maxAttempts,
        job.runAfter,
        pool,
        job.idempotencyKey ?? null,
        at,
        at,
      );
    this.onEnqueued?.(job);
    return { job, created: true };
  }

  /**
   * Claims the oldest ready job (or one whose lease expired) in the given pools for `leaseMs`. Each
   * claim increments the job's fencing token: a worker that lost its lease can no longer heartbeat,
   * write results, or complete the job.
   */
  claim(
    now: Date,
    leaseMs: number,
    options: { pools?: readonly string[]; kinds?: readonly JobKind[]; workerId?: string } = {},
  ): JobEntry | undefined {
    const at = now.toISOString();
    const pools = options.pools ?? ['default', CONTROL_POOL];
    const kinds = options.kinds ?? ['SCAN', 'REASSESS', 'KB_SYNC'];
    return this.db.transaction(() => {
      const row = this.db
        .prepare(
          `SELECT * FROM jobs WHERE ((status = 'QUEUED' AND run_after <= ?) OR (status = 'RUNNING' AND lease_until <= ?))
             AND pool IN (SELECT value FROM json_each(?)) AND kind IN (SELECT value FROM json_each(?))
           ORDER BY run_after, created_at LIMIT 1`,
        )
        .get(at, at, JSON.stringify(pools), JSON.stringify(kinds)) as JobRow | undefined;
      if (!row) return undefined;
      const lease = new Date(now.getTime() + leaseMs).toISOString();
      this.db
        .prepare(
          "UPDATE jobs SET status = 'RUNNING', attempts = attempts + 1, fencing = fencing + 1, worker_id = ?, lease_until = ?, updated_at = ? WHERE job_id = ?",
        )
        .run(options.workerId ?? LOCAL_WORKER, lease, at, row.job_id);
      return this.job(row.job_id);
    })();
  }

  /**
   * Claims a specific job regardless of pool and backoff (an external orchestrator decides when it
   * runs). Returns undefined when the job is finished or currently leased by someone else.
   */
  claimById(jobId: string, now: Date, leaseMs: number, workerId: string): JobEntry | undefined {
    const at = now.toISOString();
    return this.db.transaction(() => {
      const changed = this.db
        .prepare(
          `UPDATE jobs SET status = 'RUNNING', attempts = attempts + 1, fencing = fencing + 1, worker_id = ?, lease_until = ?, updated_at = ?
           WHERE job_id = ? AND (status = 'QUEUED' OR (status = 'RUNNING' AND lease_until <= ?))`,
        )
        .run(workerId, new Date(now.getTime() + leaseMs).toISOString(), at, jobId, at).changes;
      return changed ? this.job(jobId) : undefined;
    })();
  }

  /** True when `fencing` is the job's current token and its lease is still running. */
  holdsLease(jobId: string, fencing: number, now: Date): boolean {
    const job = this.job(jobId);
    return Boolean(
      job &&
        job.status === 'RUNNING' &&
        job.fencing === fencing &&
        job.leaseUntil &&
        job.leaseUntil > now.toISOString(),
    );
  }

  /** Extends the lease; false when the lease was lost (expired and claimed again, or finished). */
  heartbeat(jobId: string, fencing: number, now: Date, leaseMs: number): string | undefined {
    const lease = new Date(now.getTime() + leaseMs).toISOString();
    const changed = this.db
      .prepare(
        "UPDATE jobs SET lease_until = ?, updated_at = ? WHERE job_id = ? AND fencing = ? AND status = 'RUNNING' AND lease_until > ?",
      )
      .run(lease, now.toISOString(), jobId, fencing, now.toISOString()).changes;
    return changed ? lease : undefined;
  }

  /** Records success; with a fencing token, only the current lease holder may complete the job. */
  complete(jobId: string, result: Record<string, unknown>, now: Date, fencing?: number): boolean {
    return (
      this.db
        .prepare(
          `UPDATE jobs SET status = 'SUCCEEDED', result = ?, error = NULL, lease_until = NULL, updated_at = ?
           WHERE job_id = ? AND status = 'RUNNING' AND (? IS NULL OR fencing = ?)`,
        )
        .run(JSON.stringify(result), now.toISOString(), jobId, fencing ?? null, fencing ?? null).changes > 0
    );
  }

  /** Records a failure; the job is retried with backoff until it runs out of attempts. */
  fail(jobId: string, error: string, now: Date, fencing?: number): JobEntry | undefined {
    const job = this.job(jobId);
    if (job?.status !== 'RUNNING' || (fencing !== undefined && job.fencing !== fencing)) return undefined;
    const retry = job.attempts < job.maxAttempts;
    const runAfter = new Date(now.getTime() + 60_000 * 5 ** (job.attempts - 1)).toISOString();
    this.db
      .prepare(
        'UPDATE jobs SET status = ?, error = ?, run_after = ?, lease_until = NULL, updated_at = ? WHERE job_id = ?',
      )
      .run(
        retry ? 'QUEUED' : 'FAILED',
        error.slice(0, 4000),
        retry ? runAfter : job.runAfter,
        now.toISOString(),
        jobId,
      );
    return this.job(jobId);
  }

  job(jobId: string): JobEntry | undefined {
    const row = this.db.prepare('SELECT * FROM jobs WHERE job_id = ?').get(jobId) as JobRow | undefined;
    return row ? toJob(row) : undefined;
  }

  jobByKey(key: string): JobEntry | undefined {
    const row = this.db.prepare('SELECT * FROM jobs WHERE idempotency_key = ?').get(key) as JobRow | undefined;
    return row ? toJob(row) : undefined;
  }

  jobs(filter: { projectId?: string; status?: JobStatus; limit?: number } = {}): JobEntry[] {
    const where: string[] = [];
    const args: unknown[] = [];
    if (filter.projectId) {
      where.push('project_id = ?');
      args.push(filter.projectId);
    }
    if (filter.status) {
      where.push('status = ?');
      args.push(filter.status);
    }
    const sql = `SELECT * FROM jobs ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY created_at DESC, rowid DESC LIMIT ?`;
    return (this.db.prepare(sql).all(...args, filter.limit ?? 100) as JobRow[]).map(toJob);
  }

  // Remote workers ---------------------------------------------------------------

  /**
   * Short-lived token an operator hands to new worker hosts; single use by default, or `maxUses`
   * registrations for a scaled worker deployment (e.g. Kubernetes replicas).
   */
  createProvisioningToken(
    pools: readonly string[],
    createdBy: string,
    now: Date,
    ttlMinutes = 60,
    maxUses = 1,
  ): { token: string; expiresAt: string } {
    const token = `${PROVISION_PREFIX}${randomBytes(24).toString('base64url')}`;
    const expiresAt = new Date(now.getTime() + ttlMinutes * 60_000).toISOString();
    this.db
      .prepare(
        'INSERT INTO worker_provisioning (token_hash, pools, created_by, expires_at, max_uses) VALUES (?, ?, ?, ?, ?)',
      )
      .run(hash(token), JSON.stringify(pools), createdBy, expiresAt, maxUses);
    return { token, expiresAt };
  }

  /** Exchanges a provisioning token for a worker credential (consuming one use). */
  registerWorker(
    provisioningToken: string,
    name: string,
    capabilities: Record<string, unknown>,
    now: Date,
  ): { token: string; worker: WorkerEntry } | undefined {
    return this.db.transaction(() => {
      const row = this.db
        .prepare('SELECT pools FROM worker_provisioning WHERE token_hash = ? AND uses < max_uses AND expires_at > ?')
        .get(hash(provisioningToken), now.toISOString()) as { pools: string } | undefined;
      if (!row) return undefined;
      this.db
        .prepare('UPDATE worker_provisioning SET uses = uses + 1, used_at = ? WHERE token_hash = ?')
        .run(now.toISOString(), hash(provisioningToken));
      const token = `${WORKER_PREFIX}${randomBytes(32).toString('base64url')}`;
      const worker: WorkerEntry = {
        workerId: newId('wrk'),
        name,
        pools: JSON.parse(row.pools) as string[],
        capabilities,
        createdAt: now.toISOString(),
      };
      this.db
        .prepare(
          'INSERT INTO workers (worker_id, name, token_hash, pools, capabilities, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        )
        .run(worker.workerId, name, hash(token), row.pools, JSON.stringify(capabilities), worker.createdAt);
      return { token, worker };
    })();
  }

  authenticateWorker(token: string, now: Date): WorkerEntry | undefined {
    if (!token.startsWith(WORKER_PREFIX)) return undefined;
    const row = this.db.prepare('SELECT * FROM workers WHERE token_hash = ? AND revoked_at IS NULL').get(hash(token)) as
      | WorkerRow
      | undefined;
    if (!row) return undefined;
    this.db.prepare('UPDATE workers SET last_seen_at = ? WHERE worker_id = ?').run(now.toISOString(), row.worker_id);
    return toWorker(row);
  }

  workers(): WorkerEntry[] {
    return (this.db.prepare('SELECT * FROM workers ORDER BY created_at').all() as WorkerRow[]).map(toWorker);
  }

  revokeWorker(workerId: string, now: Date): boolean {
    return (
      this.db
        .prepare('UPDATE workers SET revoked_at = ? WHERE worker_id = ? AND revoked_at IS NULL')
        .run(now.toISOString(), workerId).changes > 0
    );
  }

  // Audit --------------------------------------------------------------------

  audit(
    actor: string,
    action: string,
    target: string | undefined,
    detail: Record<string, unknown> | undefined,
    now: Date,
  ): void {
    this.db
      .prepare('INSERT INTO audit_log (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)')
      .run(now.toISOString(), actor, action, target ?? null, detail ? JSON.stringify(detail) : null);
  }

  auditLog(limit = 200): AuditEntry[] {
    return (this.db.prepare('SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?').all(limit) as AuditRow[]).map((r) => ({
      seq: r.seq,
      at: r.at,
      actor: r.actor,
      action: r.action,
      ...(r.target ? { target: r.target } : {}),
      ...(r.detail ? { detail: JSON.parse(r.detail) as Record<string, unknown> } : {}),
    }));
  }
}

/** Constant-time comparison for shared secrets. */
export function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

interface ProjectRow {
  project_id: string;
  name: string;
  source_kind: string;
  location: string;
  default_branch: string;
  worker_pool: string;
  webhook_secret: string;
  created_at: string;
}
interface TokenRow {
  token_id: string;
  name: string;
  role: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}
interface JobRow {
  job_id: string;
  kind: string;
  project_id: string | null;
  payload: string;
  status: string;
  attempts: number;
  max_attempts: number;
  run_after: string;
  pool: string;
  fencing: number;
  worker_id: string | null;
  lease_until: string | null;
  idempotency_key: string | null;
  result: string | null;
  error: string | null;
  created_at: string;
  updated_at: string;
}
interface WorkerRow {
  worker_id: string;
  name: string;
  pools: string;
  capabilities: string;
  created_at: string;
  last_seen_at: string | null;
  revoked_at: string | null;
}
interface AuditRow {
  seq: number;
  at: string;
  actor: string;
  action: string;
  target: string | null;
  detail: string | null;
}

function toProject(r: ProjectRow): ProjectEntry {
  return {
    projectId: r.project_id,
    name: r.name,
    source: r.source_kind === 'git' ? { kind: 'git', url: r.location } : { kind: 'local', path: r.location },
    defaultBranch: r.default_branch,
    workerPool: r.worker_pool,
    webhookSecret: r.webhook_secret,
    createdAt: r.created_at,
  };
}
function toToken(r: TokenRow): TokenEntry {
  return {
    tokenId: r.token_id,
    name: r.name,
    role: r.role as Role,
    createdAt: r.created_at,
    ...(r.last_used_at ? { lastUsedAt: r.last_used_at } : {}),
    ...(r.revoked_at ? { revokedAt: r.revoked_at } : {}),
  };
}
function toJob(r: JobRow): JobEntry {
  return {
    jobId: r.job_id,
    kind: r.kind as JobKind,
    ...(r.project_id ? { projectId: r.project_id } : {}),
    payload: JSON.parse(r.payload) as Record<string, unknown>,
    status: r.status as JobStatus,
    attempts: r.attempts,
    maxAttempts: r.max_attempts,
    runAfter: r.run_after,
    pool: r.pool,
    fencing: r.fencing,
    ...(r.worker_id ? { workerId: r.worker_id } : {}),
    ...(r.lease_until ? { leaseUntil: r.lease_until } : {}),
    ...(r.idempotency_key ? { idempotencyKey: r.idempotency_key } : {}),
    ...(r.result ? { result: JSON.parse(r.result) as Record<string, unknown> } : {}),
    ...(r.error ? { error: r.error } : {}),
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}
function toWorker(r: WorkerRow): WorkerEntry {
  return {
    workerId: r.worker_id,
    name: r.name,
    pools: JSON.parse(r.pools) as string[],
    capabilities: JSON.parse(r.capabilities) as Record<string, unknown>,
    createdAt: r.created_at,
    ...(r.last_seen_at ? { lastSeenAt: r.last_seen_at } : {}),
    ...(r.revoked_at ? { revokedAt: r.revoked_at } : {}),
  };
}
