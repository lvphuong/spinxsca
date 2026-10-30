import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import type { IngestStats, KbSnapshot, KbStore } from './store';

/**
 * Imports OSV JSON files (a record, an array of records, or {"vulns": [...]}) from files or
 * directories. `authoritativeFor` declares the imported set complete for those ecosystems, which is
 * what curated or offline bundles (and evaluation fixtures) need for coverage.
 */
export function importOsvFiles(
  store: KbStore,
  paths: readonly string[],
  options: { sourceName?: string; authoritativeFor?: readonly string[] } = {},
): IngestStats & { files: number } {
  const files = paths.flatMap(collectJson).sort();
  const records: unknown[] = [];
  for (const file of files) {
    const doc = JSON.parse(readFileSync(file, 'utf8')) as unknown;
    if (Array.isArray(doc)) records.push(...doc);
    else if (doc && typeof doc === 'object' && Array.isArray((doc as { vulns?: unknown[] }).vulns)) {
      records.push(...((doc as { vulns: unknown[] }).vulns ?? []));
    } else records.push(doc);
  }
  const sourceId = `import:${options.sourceName ?? (paths.length === 1 ? basename(paths[0] as string) : 'files')}`;
  const stats = store.ingest(sourceId, records);
  for (const ecosystem of options.authoritativeFor ?? []) store.grantCoverage(sourceId, ecosystem);
  const prev = store.source(sourceId);
  store.saveSource({
    sourceId,
    kind: 'import',
    syncedAt: new Date().toISOString(),
    records: (prev?.records ?? 0) + stats.added,
  });
  return { ...stats, files: files.length };
}

/** Native OSV export of a snapshot: <outDir>/<ecosystem>/<id>.json, records byte-for-byte as stored. */
export function exportOsv(
  store: KbStore,
  snapshot: KbSnapshot,
  outDir: string,
  ecosystems?: readonly string[],
): number {
  let count = 0;
  for (const ecosystem of ecosystems ?? store.ecosystemsWithRecords(snapshot)) {
    const dir = join(outDir, ecosystem.replace(/[^A-Za-z0-9._-]/g, '_'));
    mkdirSync(dir, { recursive: true });
    for (const { id, json } of store.recordsFor(snapshot, ecosystem)) {
      writeFileSync(join(dir, `${id.replace(/[^A-Za-z0-9._-]/g, '_')}.json`), json);
      count++;
    }
  }
  return count;
}

function collectJson(path: string): string[] {
  const info = statSync(path);
  if (info.isFile()) return path.endsWith('.json') ? [path] : [];
  return readdirSync(path).flatMap((name) => collectJson(join(path, name)));
}
