import type Database from 'better-sqlite3';
import type pg from 'pg';

/**
 * Minimal SQL driver shared by the case repository on SQLite and PostgreSQL. SQL uses `?`
 * placeholders (rewritten to `$n` for PostgreSQL) and `{table}` names (prefixed with the schema).
 */
export interface SqlDriver {
  readonly dialect: 'sqlite' | 'pg';
  query<R = Record<string, unknown>>(sql: string, params?: readonly unknown[]): Promise<R[]>;
  /** Returns the number of affected rows. */
  run(sql: string, params?: readonly unknown[]): Promise<number>;
  /** Runs `fn` in one write transaction; `lockKey` serialises chained appends on PostgreSQL. */
  tx<T>(fn: (d: SqlDriver) => Promise<T>, lockKey?: string): Promise<T>;
}

const TABLE = /\{([a-z_]+)\}/g;

function bind(params: readonly unknown[]): unknown[] {
  return params.map((p) => (p !== null && typeof p === 'object' ? JSON.stringify(p) : p === undefined ? null : p));
}

/** Serialises access to one better-sqlite3 connection so async transactions never interleave. */
class Mutex {
  private tail: Promise<void> = Promise.resolve();
  async run<T>(fn: () => Promise<T>): Promise<T> {
    const prev = this.tail;
    let release!: () => void;
    this.tail = new Promise((r) => {
      release = r;
    });
    await prev;
    try {
      return await fn();
    } finally {
      release();
    }
  }
}

export function sqliteDriver(db: Database.Database): SqlDriver {
  const mutex = new Mutex();
  const sql = (s: string) => s.replace(TABLE, '$1');
  const inner: SqlDriver = {
    dialect: 'sqlite',
    async query<R>(s: string, params: readonly unknown[] = []) {
      return db.prepare(sql(s)).all(...bind(params)) as R[];
    },
    async run(s, params = []) {
      return db.prepare(sql(s)).run(...bind(params)).changes;
    },
    async tx(fn) {
      return fn(inner);
    },
  };
  return {
    dialect: 'sqlite',
    query: (s, p) => mutex.run(() => inner.query(s, p)),
    run: (s, p) => mutex.run(() => inner.run(s, p)),
    tx: (fn) =>
      mutex.run(async () => {
        db.exec('BEGIN IMMEDIATE');
        try {
          const out = await fn(inner);
          db.exec('COMMIT');
          return out;
        } catch (err) {
          if (db.inTransaction) db.exec('ROLLBACK');
          throw err;
        }
      }),
  };
}

export function pgDriver(pool: pg.Pool, schema: string, ready: Promise<void>): SqlDriver {
  const sql = (s: string) => {
    let n = 0;
    return s.replace(TABLE, `"${schema}".$1`).replace(/\?/g, () => `$${++n}`);
  };
  const on = (c: Pick<pg.PoolClient, 'query'>): Omit<SqlDriver, 'tx'> => ({
    dialect: 'pg',
    async query<R>(s: string, params: readonly unknown[] = []) {
      await ready;
      return (await c.query(sql(s), bind(params))).rows as R[];
    },
    async run(s, params = []) {
      await ready;
      return (await c.query(sql(s), bind(params))).rowCount ?? 0;
    },
  });
  const driver: SqlDriver = {
    ...on(pool),
    async tx(fn, lockKey) {
      await ready;
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        if (lockKey) await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`${schema}:${lockKey}`]);
        const txDriver: SqlDriver = { ...on(client), tx: (inner) => inner(txDriver) };
        const out = await fn(txDriver);
        await client.query('COMMIT');
        return out;
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        client.release();
      }
    },
  };
  return driver;
}

/** jsonb comes back parsed; SQLite text comes back as a string. */
export function fromJson<T>(value: unknown): T {
  return (typeof value === 'string' ? JSON.parse(value) : value) as T;
}
