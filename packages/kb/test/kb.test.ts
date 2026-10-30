import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  exportOsv,
  forEachZipEntry,
  importOsvFiles,
  KbStore,
  LocalKnowledgeBase,
  materializeOsvScannerDb,
  syncEcosystem,
  syncPackages,
  writeZip,
} from '../src/index';

const FIXTURES = resolve(__dirname, '../../../evals/fixtures/osv');
let dir: string;
let store: KbStore;

const record = (id: string, extra: Record<string, unknown> = {}) => ({
  id,
  modified: '2026-01-01T00:00:00Z',
  aliases: [`CVE-${id}`],
  affected: [
    {
      package: { ecosystem: 'npm', name: 'left-pad' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.3.0' }] }],
    },
  ],
  ...extra,
});

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'spx-kb-'));
  store = KbStore.open(join(dir, 'kb'));
});
afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

describe('KbStore', () => {
  it('keeps immutable revisions and content-addressed snapshots', () => {
    expect(store.ingest('t', [record('A'), record('B'), { notARecord: true }])).toEqual({
      added: 2,
      updated: 0,
      unchanged: 0,
      invalid: 1,
    });
    const s1 = store.createSnapshot();
    expect(store.createSnapshot().snapshotId).toBe(s1.snapshotId);
    expect(store.ingest('t', [record('A')])).toMatchObject({ unchanged: 1 });
    expect(store.ingest('t', [record('A', { modified: '2026-02-01T00:00:00Z' }), record('C')])).toMatchObject({
      added: 1,
      updated: 1,
    });
    const s2 = store.createSnapshot();
    expect(s2.snapshotId).not.toBe(s1.snapshotId);
    const diff = store.diff(s1, s2);
    expect([...diff.added]).toEqual(['C']);
    expect([...diff.modified]).toEqual(['A']);
    expect(store.lookup('A', s1)?.record.modified).toBe('2026-01-01T00:00:00Z');
    expect(store.lookup('A')?.record.modified).toBe('2026-02-01T00:00:00Z');
    expect(store.lookup('CVE-B')?.record.id).toBe('B');
  });

  it('tracks ecosystem and package coverage per snapshot', () => {
    store.grantCoverage('api', 'PyPI', ['Django_REST.framework']);
    const s1 = store.createSnapshot();
    expect(store.covers(s1, 'PyPI', 'django-rest-framework')).toBe(true);
    expect(store.covers(s1, 'PyPI', 'requests')).toBe(false);
    store.grantCoverage('mirror', 'npm');
    const s2 = store.createSnapshot();
    expect(s2.ecosystems).toEqual(['npm']);
    expect(store.covers(s2, 'npm', 'anything')).toBe(true);
    expect(store.covers(s1, 'npm', 'anything')).toBe(false);
  });

  it('excludes withdrawn advisories from materialized databases', async () => {
    store.ingest('t', [record('A'), record('W', { withdrawn: '2026-03-01T00:00:00Z' })]);
    const snapshot = store.createSnapshot();
    const out = await materializeOsvScannerDb(store, snapshot, ['npm', 'PyPI'], join(dir, 'cache'));
    const names: string[] = [];
    await forEachZipEntry(join(out, 'osv-scalibr', 'npm', 'all.zip'), (name, data) => {
      names.push(name);
      expect(JSON.parse(Buffer.from(data).toString()).id).toBe('A');
    });
    expect(names).toEqual(['A.json']);
    expect(existsSync(join(out, 'osv-scalibr', 'PyPI', 'all.zip'))).toBe(true);
  });
});

describe('import and export', () => {
  it('imports the evaluation fixtures as authoritative and exports them natively', async () => {
    const stats = importOsvFiles(store, [FIXTURES], {
      sourceName: 'fixtures',
      authoritativeFor: ['npm', 'PyPI', 'Maven'],
    });
    expect(stats.added).toBe(13);
    const snapshot = store.createSnapshot();
    expect(snapshot.ecosystems).toEqual(['Maven', 'PyPI', 'npm']);
    expect(snapshot.recordCount).toBe(13);
    const out = join(dir, 'export');
    expect(exportOsv(store, snapshot, out, ['PyPI'])).toBe(5);
    expect(readdirSync(join(out, 'PyPI')).sort()[0]).toBe('GHSA-j8r2-6x86-q33q.json');
    const kb = LocalKnowledgeBase.open(join(dir, 'kb2'));
    importOsvFiles(kb.store, [join(FIXTURES, 'npm')], { authoritativeFor: ['npm'] });
    kb.store.createSnapshot();
    const ref = await kb.resolveSnapshot();
    expect(ref?.ecosystems).toEqual(['npm']);
    expect(await kb.covers(ref?.snapshotId as string, 'npm', 'lodash')).toBe(true);
    kb.close();
  });
});

describe('sync', () => {
  function mockFetch(routes: Record<string, () => Response>): { fetch: typeof fetch; calls: string[] } {
    const calls: string[] = [];
    const fn = (async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push(`${init?.method ?? 'GET'} ${url}`);
      const route = routes[url];
      if (!route) return new Response('not found', { status: 404 });
      return route();
    }) as typeof fetch;
    return { fetch: fn, calls };
  }

  it('mirrors an ecosystem from its dump, then syncs incrementally', async () => {
    const zipPath = join(dir, 'dump.zip');
    await writeZip(
      zipPath,
      [record('A'), record('B', { modified: '2026-01-02T00:00:00Z' })].map((r) => ({
        name: `${r.id}.json`,
        data: Buffer.from(JSON.stringify(r)),
      })),
    );
    const base = 'https://bucket.test';
    let csv = '2026-01-02T00:00:00Z,B\n2026-01-01T00:00:00Z,A\n';
    const { fetch, calls } = mockFetch({
      [`${base}/npm/all.zip`]: () => new Response(readFileSync(zipPath), { headers: { etag: '"v1"' } }),
      [`${base}/npm/modified_id.csv`]: () => new Response(csv),
      [`${base}/npm/C.json`]: () => new Response(JSON.stringify(record('C', { modified: '2026-01-03T00:00:00Z' }))),
    });
    const options = { fetch, bucketUrl: base, downloadDir: join(dir, 'downloads') };
    const full = await syncEcosystem(store, 'npm', options);
    expect(full).toMatchObject({ mode: 'full', stats: { added: 2 } });
    expect(store.source('osv:ecosystem:npm')?.cursor).toBe('2026-01-02T00:00:00Z');
    expect(store.createSnapshot().ecosystems).toEqual(['npm']);

    expect((await syncEcosystem(store, 'npm', options)).mode).toBe('unchanged');
    csv = `2026-01-03T00:00:00Z,C\n${csv}`;
    const inc = await syncEcosystem(store, 'npm', options);
    expect(inc).toMatchObject({ mode: 'incremental', stats: { added: 1 } });
    expect(calls.filter((c) => c.endsWith('all.zip'))).toHaveLength(1);
  });

  it('syncs advisories for project packages through the OSV API', async () => {
    const api = 'https://api.test';
    const { fetch, calls } = mockFetch({
      [`${api}/v1/querybatch`]: () =>
        new Response(JSON.stringify({ results: [{ vulns: [{ id: 'A', modified: '2026-01-01T00:00:00Z' }] }, {}] })),
      [`${api}/v1/vulns/A`]: () => new Response(JSON.stringify(record('A'))),
    });
    const result = await syncPackages(
      store,
      [
        { ecosystem: 'npm', name: 'left-pad' },
        { ecosystem: 'npm', name: 'is-odd' },
      ],
      { fetch, apiUrl: api },
    );
    expect(result).toMatchObject({ packages: 2, advisories: 1, stats: { added: 1 } });
    const snapshot = store.createSnapshot();
    expect(store.covers(snapshot, 'npm', 'is-odd')).toBe(true);
    expect(store.covers(snapshot, 'npm', 'lodash')).toBe(false);
    await syncPackages(store, [{ ecosystem: 'npm', name: 'left-pad' }], { fetch, apiUrl: api });
    expect(calls.filter((c) => c.endsWith('/v1/vulns/A'))).toHaveLength(1);
    expect(store.createSnapshot().snapshotId).toBe(snapshot.snapshotId);
  });
});
