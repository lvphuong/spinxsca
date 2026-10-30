import { existsSync, mkdirSync, readdirSync, renameSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { KbSnapshot, KbStore } from './store';
import { writeZip } from './zip';

/**
 * Builds the offline database layout osv-scanner reads (<dir>/osv-scalibr/<ecosystem>/all.zip) from
 * exactly the records of one snapshot, so dependency matching is reproducible regardless of upstream
 * changes. Results are cached per snapshot; older materializations are pruned.
 */
export async function materializeOsvScannerDb(
  store: KbStore,
  snapshot: KbSnapshot,
  ecosystems: readonly string[],
  cacheRoot: string,
  keep = 3,
): Promise<string> {
  const dir = join(cacheRoot, snapshot.snapshotId);
  for (const ecosystem of ecosystems) {
    const target = join(dir, 'osv-scalibr', ecosystem, 'all.zip');
    if (existsSync(target)) continue;
    mkdirSync(join(dir, 'osv-scalibr', ecosystem), { recursive: true });
    const tmp = `${target}.${process.pid}.tmp`;
    await writeZip(
      tmp,
      (function* () {
        for (const { id, json } of store.recordsFor(snapshot, ecosystem)) yield { name: `${id}.json`, data: json };
      })(),
    );
    renameSync(tmp, target);
  }
  prune(cacheRoot, snapshot.snapshotId, keep);
  return dir;
}

function prune(cacheRoot: string, current: string, keep: number): void {
  if (!existsSync(cacheRoot)) return;
  const entries = readdirSync(cacheRoot)
    .filter((name) => name !== current && name.startsWith('kbs_'))
    .map((name) => ({ name, mtime: statSync(join(cacheRoot, name)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);
  for (const entry of entries.slice(Math.max(0, keep - 1)))
    rmSync(join(cacheRoot, entry.name), { recursive: true, force: true });
}
