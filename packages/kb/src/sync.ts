import { createWriteStream, existsSync, mkdirSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { IngestStats, KbStore } from './store';
import { forEachZipEntry } from './zip';

export const OSV_BUCKET = 'https://osv-vulnerabilities.storage.googleapis.com';
export const OSV_API = 'https://api.osv.dev';
const BATCH = 2000;
const CONCURRENCY = 8;

export interface SyncOptions {
  fetch?: typeof fetch;
  bucketUrl?: string;
  apiUrl?: string;
  /** Directory for downloaded ecosystem dumps (kept for conditional re-download). */
  downloadDir: string;
  /** Above this many changed records an incremental sync falls back to the full dump. */
  maxIncremental?: number;
  onProgress?: (message: string) => void;
}

export interface EcosystemSyncResult {
  ecosystem: string;
  mode: 'full' | 'incremental' | 'unchanged';
  stats: IngestStats;
}

const EMPTY: IngestStats = { added: 0, updated: 0, unchanged: 0, invalid: 0 };

/**
 * Mirrors one OSV ecosystem. The first sync ingests the ecosystem dump; later syncs read
 * modified_id.csv (newest first) and fetch only records changed since the stored cursor.
 */
export async function syncEcosystem(
  store: KbStore,
  ecosystem: string,
  options: SyncOptions,
): Promise<EcosystemSyncResult> {
  const http = options.fetch ?? fetch;
  const bucket = options.bucketUrl ?? OSV_BUCKET;
  const sourceId = `osv:ecosystem:${ecosystem}`;
  const state = store.source(sourceId);
  const progress = options.onProgress ?? (() => {});

  if (state?.cursor) {
    const res = await http(`${bucket}/${encodeURIComponent(ecosystem)}/modified_id.csv`);
    if (!res.ok) throw new Error(`OSV index for ${ecosystem}: HTTP ${res.status}`);
    const changed: Array<{ modified: string; id: string }> = [];
    for (const line of (await res.text()).split('\n')) {
      const [modified, id] = line.trim().split(',');
      if (!modified || !id) continue;
      if (modified <= state.cursor) break;
      changed.push({ modified, id });
    }
    if (changed.length === 0) {
      store.saveSource({ ...state, syncedAt: new Date().toISOString() });
      return { ecosystem, mode: 'unchanged', stats: EMPTY };
    }
    if (changed.length <= (options.maxIncremental ?? 5000)) {
      progress(`${ecosystem}: fetching ${changed.length} changed advisories`);
      const records = await mapLimit(changed, CONCURRENCY, async ({ id }) => {
        const r = await http(`${bucket}/${encodeURIComponent(ecosystem)}/${encodeURIComponent(id)}.json`);
        if (!r.ok) throw new Error(`OSV record ${id}: HTTP ${r.status}`);
        return r.json() as Promise<unknown>;
      });
      const stats = store.ingest(sourceId, records);
      store.saveSource({
        ...state,
        cursor: changed[0]?.modified ?? state.cursor,
        syncedAt: new Date().toISOString(),
        records: state.records + stats.added,
      });
      return { ecosystem, mode: 'incremental', stats };
    }
  }

  mkdirSync(options.downloadDir, { recursive: true });
  const zipPath = join(options.downloadDir, `${ecosystem.replace(/[^A-Za-z0-9._-]/g, '_')}-all.zip`);
  const headers: Record<string, string> = {};
  if (state?.etag && existsSync(zipPath)) headers['If-None-Match'] = state.etag;
  const res = await http(`${bucket}/${encodeURIComponent(ecosystem)}/all.zip`, { headers });
  if (res.status !== 304) {
    if (!res.ok || !res.body) throw new Error(`OSV dump for ${ecosystem}: HTTP ${res.status}`);
    const size = Number(res.headers.get('content-length') ?? 0);
    progress(`${ecosystem}: downloading ${size ? `${(size / 1e6).toFixed(0)} MB` : 'dump'}`);
    const tmp = `${zipPath}.${process.pid}.tmp`;
    await pipeline(Readable.fromWeb(res.body as never), createWriteStream(tmp));
    renameSync(tmp, zipPath);
  }
  progress(`${ecosystem}: ingesting advisories`);
  const stats: IngestStats = { ...EMPTY };
  let batch: unknown[] = [];
  let cursor = state?.cursor ?? '';
  const flush = () => {
    const s = store.ingest(sourceId, batch);
    stats.added += s.added;
    stats.updated += s.updated;
    stats.unchanged += s.unchanged;
    stats.invalid += s.invalid;
    batch = [];
  };
  await forEachZipEntry(zipPath, (name, data) => {
    if (!name.endsWith('.json')) return;
    try {
      const record = JSON.parse(Buffer.from(data).toString('utf8')) as { modified?: string };
      if (record.modified && record.modified > cursor) cursor = record.modified;
      batch.push(record);
    } catch {
      stats.invalid++;
    }
    if (batch.length >= BATCH) flush();
  });
  flush();
  store.grantCoverage(sourceId, ecosystem);
  store.saveSource({
    sourceId,
    kind: 'osv-ecosystem',
    ecosystem,
    ...(res.headers.get('etag')
      ? { etag: res.headers.get('etag') as string }
      : state?.etag
        ? { etag: state.etag }
        : {}),
    ...(cursor ? { cursor } : {}),
    syncedAt: new Date().toISOString(),
    records: stats.added + stats.updated + stats.unchanged,
  });
  return { ecosystem, mode: 'full', stats };
}

export interface PackageQuery {
  ecosystem: string;
  name: string;
}

/**
 * Package-scoped sync through the OSV API: all advisories of the given packages (any version), so
 * later dependency versions can be matched offline. Coverage is granted per package (ADR-007).
 */
export async function syncPackages(
  store: KbStore,
  packages: readonly PackageQuery[],
  options: Omit<SyncOptions, 'downloadDir'>,
): Promise<{ packages: number; advisories: number; stats: IngestStats }> {
  const http = options.fetch ?? fetch;
  const api = options.apiUrl ?? OSV_API;
  const unique = [...new Map(packages.map((p) => [`${p.ecosystem}\u0000${p.name}`, p])).values()];
  const ids = new Map<string, string | undefined>();
  for (let i = 0; i < unique.length; i += 1000) {
    const slice = unique.slice(i, i + 1000);
    const queries = slice.map((p) => ({ package: { ecosystem: p.ecosystem, name: p.name } }));
    const res = await post(http, `${api}/v1/querybatch`, { queries });
    const results = (res.results ?? []) as Array<{
      vulns?: Array<{ id: string; modified?: string }>;
      next_page_token?: string;
    }>;
    for (const [index, result] of results.entries()) {
      for (const v of result.vulns ?? []) ids.set(v.id, v.modified);
      let token = result.next_page_token;
      while (token) {
        const page = await post(http, `${api}/v1/query`, { ...queries[index], page_token: token });
        for (const v of (page.vulns ?? []) as Array<{ id: string; modified?: string }>) ids.set(v.id, v.modified);
        token = page.next_page_token as string | undefined;
      }
    }
  }
  const sameTime = (a: string | undefined, b: string | undefined) => !!a && !!b && Date.parse(a) === Date.parse(b);
  const toFetch = [...ids.entries()]
    .filter(([id, modified]) => !sameTime(modified, store.latestModified(id)))
    .map(([id]) => id);
  options.onProgress?.(`OSV API: ${ids.size} advisories for ${unique.length} packages, fetching ${toFetch.length}`);
  const records = await mapLimit(toFetch, CONCURRENCY, async (id) => {
    const r = await http(`${api}/v1/vulns/${encodeURIComponent(id)}`);
    if (!r.ok) throw new Error(`OSV API ${id}: HTTP ${r.status}`);
    return r.json() as Promise<unknown>;
  });
  const sourceId = 'osv:api';
  const stats = store.ingest(sourceId, records);
  const byEcosystem = new Map<string, string[]>();
  for (const p of unique) byEcosystem.set(p.ecosystem, [...(byEcosystem.get(p.ecosystem) ?? []), p.name]);
  for (const [ecosystem, names] of byEcosystem) store.grantCoverage(sourceId, ecosystem, names);
  const prev = store.source(sourceId);
  store.saveSource({
    sourceId,
    kind: 'osv-api',
    syncedAt: new Date().toISOString(),
    records: (prev?.records ?? 0) + stats.added,
  });
  return { packages: unique.length, advisories: ids.size, stats };
}

async function post(http: typeof fetch, url: string, body: unknown): Promise<Record<string, unknown>> {
  const res = await http(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return (await res.json()) as Record<string, unknown>;
}

async function mapLimit<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index] as T);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}
