import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { KbStore, LocalKnowledgeBase, nvdRecord, parseEpssCsv, syncEpss, syncKev, syncNvd } from '../src/index';

let dir: string;
let store: KbStore;
const advisory = (id: string, cve: string, pkg = 'lodash') => ({
  id,
  modified: '2026-01-01T00:00:00Z',
  aliases: [cve],
  affected: [
    {
      package: { ecosystem: 'npm', name: pkg },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
    },
  ],
});
const kevFeed = (version: string, cves: string[]) => ({
  catalogVersion: version,
  dateReleased: `${version}T00:00:00.000Z`,
  vulnerabilities: cves.map((cveID) => ({
    cveID,
    dateAdded: '2026-10-01',
    dueDate: '2026-10-22',
    knownRansomwareCampaignUse: cveID === 'CVE-2026-0002' ? 'Known' : 'Unknown',
    vulnerabilityName: 'x',
  })),
});
const epssCsv = (date: string, rows: Array<[string, number, number]>) =>
  `#model_version:v2025.03.14,score_date:${date}T00:00:00Z\ncve,epss,percentile\n${rows.map((r) => r.join(',')).join('\n')}\n`;
const respond = (body: unknown, init: ResponseInit = {}) =>
  (async () =>
    new Response(
      typeof body === 'string' || body instanceof Uint8Array
        ? (body as ConstructorParameters<typeof Response>[0])
        : JSON.stringify(body),
      init,
    )) as unknown as typeof fetch;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'spx-intel-'));
  store = KbStore.open(join(dir, 'kb'));
  store.ingest('t', [advisory('GHSA-aaaa', 'CVE-2026-0001'), advisory('GHSA-bbbb', 'CVE-2026-0002', 'express')]);
});
afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

describe('intelligence sources', () => {
  it('parses EPSS CSV headers and rows', () => {
    const parsed = parseEpssCsv(epssCsv('2026-10-29', [['CVE-2026-0001', 0.5, 0.97]]));
    expect(parsed).toMatchObject({ modelVersion: 'v2025.03.14', scoreDate: '2026-10-29T00:00:00Z' });
    expect(parsed.scores.get('CVE-2026-0001')).toEqual([0.5, 0.97]);
    expect(() => parseEpssCsv('cve,epss\n')).toThrow('score_date');
  });

  it('prefers CVSS v4 then v3.1, NVD primary first, and keeps CWE ids', () => {
    const record = nvdRecord({
      id: 'CVE-1',
      lastModified: '2026-10-01T00:00:00.000',
      metrics: {
        cvssMetricV31: [
          {
            source: 'other@x',
            type: 'Secondary',
            cvssData: { version: '3.1', baseScore: 5, vectorString: 'CVSS:3.1/AV:N' },
          },
          {
            source: 'nvd@nist.gov',
            type: 'Primary',
            cvssData: { version: '3.1', baseScore: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L' },
          },
        ],
      },
      weaknesses: [{ description: [{ value: 'CWE-89' }, { value: 'NVD-CWE-Other' }] }],
    });
    expect(record.cvss).toEqual({
      version: '3.1',
      baseScore: 9.8,
      vector: 'CVSS:3.1/AV:N/AC:L',
      source: 'nvd@nist.gov',
    });
    expect(record.cwes).toEqual(['CWE-89']);
  });

  it('stores KEV, EPSS and NVD as revisions included in snapshots, resolved through aliases', async () => {
    const before = store.createSnapshot();
    expect(before.intelUpto).toBe(0);
    await syncKev(store, { fetch: respond(kevFeed('2026.10.28', ['CVE-2026-0002', 'CVE-2099-9999'])) });
    await syncEpss(store, {
      fetch: respond(
        gzipSync(
          epssCsv('2026-10-29', [
            ['CVE-2026-0001', 0.02, 0.6],
            ['CVE-2026-0002', 0.9, 0.99],
            ['CVE-2000-0001', 0.1, 0.5],
          ]),
        ),
      ),
    });
    let requests = 0;
    const nvdFetch = (async (url: string) => {
      requests++;
      expect(String(url)).toContain('startIndex=0');
      return new Response(
        JSON.stringify({
          totalResults: 2,
          vulnerabilities: [
            {
              cve: {
                id: 'CVE-2026-0001',
                lastModified: '2026-10-01',
                metrics: {
                  cvssMetricV31: [
                    {
                      type: 'Primary',
                      source: 'nvd@nist.gov',
                      cvssData: { version: '3.1', baseScore: 7.5, vectorString: 'CVSS:3.1/AV:N' },
                    },
                  ],
                },
                weaknesses: [{ description: [{ value: 'CWE-1321' }] }],
              },
            },
            { cve: { id: 'CVE-1999-0001', lastModified: '2026-10-01' } },
          ],
        }),
      );
    }) as unknown as typeof fetch;
    expect(await syncNvd(store, { fetch: nvdFetch, sleep: async () => {} })).toMatchObject({
      entries: 1,
      revisions: 1,
    });
    expect(requests).toBe(1);

    const after = store.createSnapshot();
    expect(after.snapshotId).not.toBe(before.snapshotId);
    expect(after.intelUpto).toBe(3);
    expect(store.intelFor(after, ['GHSA-bbbb'])).toEqual({
      cves: ['CVE-2026-0002'],
      kev: { dateAdded: '2026-10-01', dueDate: '2026-10-22', ransomware: true, catalogVersion: '2026.10.28' },
      epss: { score: 0.9, percentile: 0.99, date: '2026-10-29T00:00:00Z' },
    });
    expect(store.intelFor(after, ['GHSA-aaaa'])).toEqual({
      cves: ['CVE-2026-0001'],
      epss: { score: 0.02, percentile: 0.6, date: '2026-10-29T00:00:00Z' },
      cvss: { version: '3.1', baseScore: 7.5, vector: 'CVSS:3.1/AV:N', source: 'nvd@nist.gov' },
      cwes: ['CWE-1321'],
    });
    // Older snapshots do not see later intelligence.
    expect(store.intelFor(before, ['GHSA-bbbb'])).toBeUndefined();
    // EPSS keeps only CVEs referenced by advisories.
    expect(store.source('intel:epss')?.records).toBe(2);
    // Re-syncing identical data does not create a new snapshot.
    await syncKev(store, { fetch: respond(kevFeed('2026.10.28', ['CVE-2026-0002', 'CVE-2099-9999'])) });
    expect(store.createSnapshot().snapshotId).toBe(after.snapshotId);
  });

  it('reports advisories newly listed in KEV as modified, and the packages they name', async () => {
    await syncKev(store, { fetch: respond(kevFeed('2026.10.27', [])) });
    const first = store.createSnapshot();
    await syncKev(store, { fetch: respond(kevFeed('2026.10.28', ['CVE-2026-0001'])) });
    const second = store.createSnapshot();
    expect(store.diff(first, second)).toEqual({ added: new Set(), modified: new Set(['GHSA-aaaa']) });
    const kb = LocalKnowledgeBase.open(join(dir, 'kb'));
    try {
      expect(await kb.changedPackages(first.snapshotId, second.snapshotId)).toEqual([
        { ecosystem: 'npm', name: 'lodash', advisory: 'GHSA-aaaa' },
      ]);
      expect((await kb.intel(second.snapshotId, ['GHSA-aaaa']))?.kev?.catalogVersion).toBe('2026.10.28');
    } finally {
      kb.close();
    }
  });

  it('uses a conditional request for KEV and incremental windows for NVD', async () => {
    let seenEtag: string | null = null;
    await syncKev(store, { fetch: respond(kevFeed('2026.10.28', []), { headers: { etag: '"v1"' } }) });
    const notModified = (async (_url: string, init?: RequestInit) => {
      seenEtag = new Headers(init?.headers).get('if-none-match');
      return new Response(null, { status: 304 });
    }) as unknown as typeof fetch;
    expect((await syncKev(store, { fetch: notModified })).mode).toBe('not-modified');
    expect(seenEtag).toBe('"v1"');

    const urls: string[] = [];
    const page = (async (url: string) => {
      urls.push(String(url));
      return new Response(JSON.stringify({ totalResults: 0, vulnerabilities: [] }));
    }) as unknown as typeof fetch;
    await syncNvd(store, { fetch: page, now: () => new Date('2026-10-01T00:00:00Z'), sleep: async () => {} });
    await syncNvd(store, { fetch: page, now: () => new Date('2026-10-29T00:00:00Z'), sleep: async () => {} });
    expect(urls[0]).not.toContain('lastModStartDate');
    expect(urls[1]).toContain('lastModStartDate=2026-10-01T00%3A00%3A00.000Z');
    expect(urls[1]).toContain('lastModEndDate=2026-10-29T00%3A00%3A00.000Z');
  });
});
