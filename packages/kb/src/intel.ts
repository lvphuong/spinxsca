import { gunzipSync } from 'node:zlib';
import { z } from 'zod';
import type { KbStore } from './store';

/**
 * CISA publishes the catalogue on cisa.gov and in the cisagov/kev-data repository; the cisa.gov CDN
 * rejects non-browser clients, so the repository copy is the default.
 */
export const KEV_URL = 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json';
const USER_AGENT = 'spinxsca-kb (+https://github.com/spinxsca/spinxsca)';
export const EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';
export const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

/** KEV dataset as stored: one immutable revision per catalog release. */
export interface KevDataset {
  catalogVersion: string;
  dateReleased: string;
  entries: Record<string, { dateAdded: string; dueDate?: string; ransomware: boolean; name?: string }>;
}

/** EPSS dataset as stored: scores for the CVEs referenced by the knowledge base. */
export interface EpssDataset {
  modelVersion: string;
  scoreDate: string;
  scores: Record<string, [score: number, percentile: number]>;
}

/** One NVD CVE record reduced to what triage needs. */
export interface NvdRecord {
  published?: string;
  lastModified?: string;
  status?: string;
  cvss?: { version: string; baseScore: number; vector: string; source: string };
  cwes: string[];
}

export interface IntelSyncOptions {
  fetch?: typeof fetch;
  url?: string;
  onProgress?: (message: string) => void;
}

export interface IntelSyncResult {
  source: 'kev' | 'epss' | 'nvd';
  mode: 'updated' | 'unchanged' | 'not-modified';
  entries: number;
  revisions: number;
}

const KevFeed = z.object({
  catalogVersion: z.string(),
  dateReleased: z.string(),
  vulnerabilities: z.array(
    z.object({
      cveID: z.string(),
      dateAdded: z.string(),
      dueDate: z.string().optional(),
      knownRansomwareCampaignUse: z.string().optional(),
      vulnerabilityName: z.string().optional(),
    }),
  ),
});

/** CISA Known Exploited Vulnerabilities catalog (conditional GET; one revision per release). */
export async function syncKev(store: KbStore, options: IntelSyncOptions = {}): Promise<IntelSyncResult> {
  const http = options.fetch ?? fetch;
  const url = options.url ?? KEV_URL;
  const state = store.source('intel:kev');
  const res = await http(url, {
    headers: { 'user-agent': USER_AGENT, ...(state?.etag ? { 'if-none-match': state.etag } : {}) },
  });
  if (res.status === 304) return { source: 'kev', mode: 'not-modified', entries: 0, revisions: 0 };
  if (!res.ok) throw new Error(`KEV download failed: HTTP ${res.status}`);
  const feed = KevFeed.parse(await res.json());
  const entries: KevDataset['entries'] = {};
  for (const v of feed.vulnerabilities) {
    entries[v.cveID] = {
      dateAdded: v.dateAdded,
      ...(v.dueDate ? { dueDate: v.dueDate } : {}),
      ransomware: (v.knownRansomwareCampaignUse ?? '').toLowerCase() === 'known',
      ...(v.vulnerabilityName ? { name: v.vulnerabilityName } : {}),
    };
  }
  const dataset: KevDataset = { catalogVersion: feed.catalogVersion, dateReleased: feed.dateReleased, entries };
  const added = store.ingestIntel('kev', '*', feed.dateReleased, dataset);
  store.saveSource({
    sourceId: 'intel:kev',
    kind: 'intel-kev',
    ...(res.headers.get('etag') ? { etag: res.headers.get('etag') as string } : {}),
    cursor: feed.catalogVersion,
    syncedAt: new Date().toISOString(),
    records: feed.vulnerabilities.length,
  });
  options.onProgress?.(
    `KEV catalog ${feed.catalogVersion}: ${feed.vulnerabilities.length} entries${added ? '' : ' (unchanged)'}`,
  );
  return {
    source: 'kev',
    mode: added ? 'updated' : 'unchanged',
    entries: feed.vulnerabilities.length,
    revisions: added ? 1 : 0,
  };
}

/**
 * FIRST EPSS daily scores. Only CVEs referenced by advisories in the knowledge base are kept, so a
 * daily revision stays small; sync dependency advisories first.
 */
export async function syncEpss(store: KbStore, options: IntelSyncOptions = {}): Promise<IntelSyncResult> {
  const http = options.fetch ?? fetch;
  const res = await http(options.url ?? EPSS_URL, { headers: { 'user-agent': USER_AGENT } });
  if (!res.ok) throw new Error(`EPSS download failed: HTTP ${res.status}`);
  const body = Buffer.from(await res.arrayBuffer());
  const text = (body[0] === 0x1f && body[1] === 0x8b ? gunzipSync(body) : body).toString('utf8');
  const parsed = parseEpssCsv(text);
  const wanted = store.referencedCves();
  const scores: EpssDataset['scores'] = {};
  for (const [cve, value] of parsed.scores) if (wanted.has(cve)) scores[cve] = value;
  const dataset: EpssDataset = { modelVersion: parsed.modelVersion, scoreDate: parsed.scoreDate, scores };
  const added = store.ingestIntel('epss', '*', parsed.scoreDate, dataset);
  store.saveSource({
    sourceId: 'intel:epss',
    kind: 'intel-epss',
    cursor: parsed.scoreDate,
    syncedAt: new Date().toISOString(),
    records: Object.keys(scores).length,
  });
  options.onProgress?.(
    `EPSS ${parsed.scoreDate} (${parsed.modelVersion}): ${Object.keys(scores).length} of ${parsed.scores.size} CVEs referenced by the knowledge base`,
  );
  return {
    source: 'epss',
    mode: added ? 'updated' : 'unchanged',
    entries: Object.keys(scores).length,
    revisions: added ? 1 : 0,
  };
}

export function parseEpssCsv(text: string): {
  modelVersion: string;
  scoreDate: string;
  scores: Map<string, [number, number]>;
} {
  const lines = text.split(/\r?\n/);
  let modelVersion = 'unknown';
  let scoreDate = '';
  const scores = new Map<string, [number, number]>();
  for (const line of lines) {
    if (!line) continue;
    if (line.startsWith('#')) {
      for (const part of line.slice(1).split(',')) {
        const [key, ...rest] = part.split(':');
        const value = rest.join(':').trim();
        if (key?.trim() === 'model_version') modelVersion = value;
        if (key?.trim() === 'score_date') scoreDate = value;
      }
      continue;
    }
    const [cve, score, percentile] = line.split(',');
    if (!cve?.startsWith('CVE-')) continue;
    const s = Number(score);
    const p = Number(percentile);
    if (Number.isFinite(s) && Number.isFinite(p)) scores.set(cve, [s, p]);
  }
  if (!scoreDate) throw new Error('EPSS file has no score_date header');
  return { modelVersion, scoreDate, scores };
}

interface NvdMetric {
  source?: string;
  type?: string;
  cvssData?: { version?: string; baseScore?: number; vectorString?: string };
}
interface NvdCve {
  id: string;
  published?: string;
  lastModified?: string;
  vulnStatus?: string;
  metrics?: Record<string, NvdMetric[] | undefined>;
  weaknesses?: Array<{ description?: Array<{ value?: string }> }>;
}

/** Best CVSS: v4.0, then v3.1, v3.0; NVD's primary score before secondary sources. */
export function nvdRecord(cve: NvdCve): NvdRecord {
  let cvss: NvdRecord['cvss'];
  for (const key of ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30']) {
    const metrics = [...(cve.metrics?.[key] ?? [])].sort(
      (a, b) => Number(b.type === 'Primary') - Number(a.type === 'Primary'),
    );
    const m = metrics.find((x) => x.cvssData?.baseScore !== undefined && x.cvssData.vectorString);
    if (m?.cvssData) {
      cvss = {
        version: m.cvssData.version ?? key.replace('cvssMetricV', '').replace(/(\d)(\d)/, '$1.$2'),
        baseScore: m.cvssData.baseScore as number,
        vector: m.cvssData.vectorString as string,
        source: m.source ?? 'nvd',
      };
      break;
    }
  }
  const cwes = [
    ...new Set(
      (cve.weaknesses ?? [])
        .flatMap((w) => (w.description ?? []).map((d) => d.value ?? ''))
        .filter((v) => /^CWE-\d+$/.test(v)),
    ),
  ].sort();
  return {
    ...(cve.published ? { published: cve.published } : {}),
    ...(cve.lastModified ? { lastModified: cve.lastModified } : {}),
    ...(cve.vulnStatus ? { status: cve.vulnStatus } : {}),
    ...(cvss ? { cvss } : {}),
    cwes,
  };
}

export interface NvdSyncOptions extends IntelSyncOptions {
  apiKey?: string;
  /** Delay between requests (NVD: 5 requests / 30 s without a key, 50 with one). */
  delayMs?: number;
  sleep?: (ms: number) => Promise<void>;
  now?: () => Date;
  pageSize?: number;
}

const NVD_WINDOW_DAYS = 120;

/**
 * NVD CVE API 2.0. The first sync pages through the whole catalogue; later syncs read the
 * lastModified window since the previous cursor (at most 120 days, NVD's limit). Only CVEs referenced
 * by advisories in the knowledge base are stored.
 */
export async function syncNvd(store: KbStore, options: NvdSyncOptions = {}): Promise<IntelSyncResult> {
  const http = options.fetch ?? fetch;
  const base = options.url ?? NVD_API;
  const sleep = options.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  const delay = options.delayMs ?? (options.apiKey ? 700 : 6500);
  const now = (options.now ?? (() => new Date()))();
  const pageSize = options.pageSize ?? 2000;
  const state = store.source('intel:nvd');
  const wanted = store.referencedCves();
  const since = state?.cursor ? new Date(state.cursor) : undefined;
  const incremental = since !== undefined && now.getTime() - since.getTime() < NVD_WINDOW_DAYS * 86_400_000;
  let startIndex = 0;
  let total = Number.POSITIVE_INFINITY;
  let kept = 0;
  let revisions = 0;
  let requests = 0;
  while (startIndex < total) {
    const params = new URLSearchParams({ resultsPerPage: String(pageSize), startIndex: String(startIndex) });
    if (incremental && since) {
      params.set('lastModStartDate', since.toISOString());
      params.set('lastModEndDate', now.toISOString());
    }
    if (requests > 0) await sleep(delay);
    requests++;
    const res = await http(`${base}?${params}`, {
      headers: { 'user-agent': USER_AGENT, ...(options.apiKey ? { apiKey: options.apiKey } : {}) },
    });
    if (!res.ok) throw new Error(`NVD request failed: HTTP ${res.status}`);
    const page = (await res.json()) as {
      totalResults?: number;
      resultsPerPage?: number;
      vulnerabilities?: Array<{ cve: NvdCve }>;
    };
    total = page.totalResults ?? 0;
    const items = page.vulnerabilities ?? [];
    for (const { cve } of items) {
      if (!wanted.has(cve.id)) continue;
      kept++;
      const record = nvdRecord(cve);
      if (store.ingestIntel('nvd', cve.id, record.lastModified ?? '', record)) revisions++;
    }
    options.onProgress?.(`NVD ${Math.min(startIndex + items.length, total)}/${total} CVEs scanned, ${kept} referenced`);
    if (items.length === 0) break;
    startIndex += items.length;
  }
  store.saveSource({
    sourceId: 'intel:nvd',
    kind: 'intel-nvd',
    cursor: now.toISOString(),
    syncedAt: now.toISOString(),
    records: (state?.records ?? 0) + revisions,
  });
  return { source: 'nvd', mode: revisions ? 'updated' : 'unchanged', entries: kept, revisions };
}
