import type Database from 'better-sqlite3';
import { caseTables } from './case/ddl';
import { MIGRATIONS as DRIZZLE_MIGRATIONS } from './migrations.generated';

/**
 * Hand-written migrations applied after the drizzle-kit ones. The case store (ADR-044) is shared with
 * PostgreSQL through one SQL implementation, so its tables are not part of the drizzle schema.
 */
const EXTRA_MIGRATIONS: ReadonlyArray<{ tag: string; statements: readonly string[] }> = [
  { tag: '0002_autonomy', statements: caseTables('sqlite') },
];

const MIGRATIONS = [...DRIZZLE_MIGRATIONS, ...EXTRA_MIGRATIONS];

/** Applies embedded migrations in order, each in its own transaction. */
export function migrate(sqlite: Database.Database): string[] {
  sqlite.exec(
    'CREATE TABLE IF NOT EXISTS __spinxsca_migrations (tag TEXT PRIMARY KEY NOT NULL, applied_at TEXT NOT NULL)',
  );
  const applied = new Set(
    (sqlite.prepare('SELECT tag FROM __spinxsca_migrations').all() as Array<{ tag: string }>).map((r) => r.tag),
  );
  const ran: string[] = [];
  for (const migration of MIGRATIONS) {
    if (applied.has(migration.tag)) continue;
    sqlite.transaction(() => {
      for (const statement of migration.statements) sqlite.exec(statement);
      sqlite
        .prepare('INSERT INTO __spinxsca_migrations (tag, applied_at) VALUES (?, ?)')
        .run(migration.tag, new Date().toISOString());
    })();
    ran.push(migration.tag);
  }
  return ran;
}
