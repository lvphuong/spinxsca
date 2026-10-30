import type Database from 'better-sqlite3';
import { MIGRATIONS } from './migrations.generated';

/** Applies embedded drizzle-kit migrations in order, each in its own transaction. */
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
