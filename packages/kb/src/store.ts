import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';
import { sha256, sha256Hex, stableStringify } from '@spinxsca/core';
import type { Digest, VulnIntel } from '@spinxsca/schemas';
import Database from 'better-sqlite3';
import type { EpssDataset, KevDataset, NvdRecord } from './intel';
import { affectedPackages, normalizePackageName, OsvRecord } from './osv';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS kb_revisions (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  record_id TEXT NOT NULL,
  content_digest TEXT NOT NULL,
  modified TEXT,
  withdrawn TEXT,
  summary TEXT,
  aliases TEXT NOT NULL,
  source_id TEXT NOT NULL,
  raw BLOB NOT NULL,
  ingested_at TEXT NOT NULL,
  UNIQUE (record_id, content_digest)
);
CREATE INDEX IF NOT EXISTS idx_kb_revisions_record ON kb_revisions (record_id, seq);
CREATE TABLE IF NOT EXISTS kb_affected (
  seq INTEGER NOT NULL,
  ecosystem TEXT NOT NULL,
  package TEXT NOT NULL,
  PRIMARY KEY (seq, ecosystem, package)
);
CREATE INDEX IF NOT EXISTS idx_kb_affected_package ON kb_affected (ecosystem, package);
CREATE TABLE IF NOT EXISTS kb_sources (
  source_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  ecosystem TEXT,
  etag TEXT,
  cursor TEXT,
  synced_at TEXT,
  records INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS kb_coverage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scope TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  package TEXT,
  source_id TEXT NOT NULL,
  granted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kb_coverage ON kb_coverage (ecosystem, package);
CREATE TABLE IF NOT EXISTS kb_intel (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  key TEXT NOT NULL,
  content_digest TEXT NOT NULL,
  released TEXT,
  data BLOB NOT NULL,
  ingested_at TEXT NOT NULL,
  UNIQUE (source, key, content_digest)
);
CREATE INDEX IF NOT EXISTS idx_kb_intel_key ON kb_intel (source, key, seq);
CREATE TABLE IF NOT EXISTS kb_snapshots (
  snapshot_id TEXT PRIMARY KEY,
  watermark INTEGER NOT NULL,
  coverage_upto INTEGER NOT NULL,
  digest TEXT NOT NULL,
  record_count INTEGER NOT NULL,
  ecosystems TEXT NOT NULL,
  created_at TEXT NOT NULL
);
`;

export interface KbSnapshot {
  snapshotId: string;
  watermark: number;
  coverageUpto: number;
  digest: Digest;
  recordCount: number;
  /** Ecosystems fully mirrored as of this snapshot. */
  ecosystems: string[];
  /** Highest KEV/EPSS/NVD revision included (0 when the snapshot has no intelligence). */
  intelUpto: number;
  createdAt: string;
}

export interface IngestStats {
  added: number;
  updated: number;
  unchanged: number;
  invalid: number;
}

export interface SourceState {
  sourceId: string;
  kind: string;
  ecosystem?: string;
  etag?: string;
  cursor?: string;
  syncedAt?: string;
  records: number;
}

interface VisibleRow {
  record_id: string;
  content_digest: string;
  withdrawn: string | null;
  seq: number;
}

/**
 * Local vulnerability knowledge base (docs/architecture/04, ADR-007): every distinct version of an
 * advisory is an immutable revision; a snapshot is a watermark over revisions plus coverage grants,
 * identified by the digest of what it contains.
 */
export class KbStore {
  readonly db: Database.Database;

  private constructor(readonly dir: string) {
    mkdirSync(dir, { recursive: true });
    this.db = new Database(join(dir, 'kb.db'));
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('busy_timeout = 5000');
    this.db.exec(SCHEMA);
    const columns = this.db.prepare('PRAGMA table_info(kb_snapshots)').all() as Array<{ name: string }>;
    if (!columns.some((c) => c.name === 'intel_upto')) {
      this.db.exec('ALTER TABLE kb_snapshots ADD COLUMN intel_upto INTEGER NOT NULL DEFAULT 0');
    }
  }

  static open(dir: string): KbStore {
    return new KbStore(dir);
  }

  close(): void {
    this.db.close();
  }

  /** Ingests records from one source in a single transaction; identical content is a no-op. */
  ingest(sourceId: string, records: Iterable<unknown>): IngestStats {
    const stats: IngestStats = { added: 0, updated: 0, unchanged: 0, invalid: 0 };
    const latest = this.db.prepare<[string], { content_digest: string }>(
      'SELECT content_digest FROM kb_revisions WHERE record_id = ? ORDER BY seq DESC LIMIT 1',
    );
    const insert = this.db.prepare(
      `INSERT OR IGNORE INTO kb_revisions (record_id, content_digest, modified, withdrawn, summary, aliases, source_id, raw, ingested_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const insertAffected = this.db.prepare(
      'INSERT OR IGNORE INTO kb_affected (seq, ecosystem, package) VALUES (?, ?, ?)',
    );
    const now = new Date().toISOString();
    this.db.transaction(() => {
      for (const raw of records) {
        const parsed = OsvRecord.safeParse(raw);
        if (!parsed.success) {
          stats.invalid++;
          continue;
        }
        const record = parsed.data;
        const canonical = stableStringify(record);
        const digest = sha256Hex(canonical);
        const previous = latest.get(record.id);
        if (previous?.content_digest === digest) {
          stats.unchanged++;
          continue;
        }
        const result = insert.run(
          record.id,
          digest,
          record.modified ?? null,
          record.withdrawn ?? null,
          record.summary ?? null,
          JSON.stringify(record.aliases ?? []),
          sourceId,
          gzipSync(canonical),
          now,
        );
        if (result.changes === 0) {
          stats.unchanged++;
          continue;
        }
        for (const pkg of affectedPackages(record)) insertAffected.run(result.lastInsertRowid, pkg.ecosystem, pkg.name);
        if (previous) stats.updated++;
        else stats.added++;
      }
    })();
    return stats;
  }

  /** Grants coverage; a grant that already exists is not repeated, so re-syncing does not change snapshots. */
  grantCoverage(sourceId: string, ecosystem: string, packages?: readonly string[]): void {
    const now = new Date().toISOString();
    const exists = this.db.prepare<[string, string, string | null], unknown>(
      'SELECT 1 FROM kb_coverage WHERE scope = ? AND ecosystem = ? AND package IS ? LIMIT 1',
    );
    const insert = this.db.prepare(
      'INSERT INTO kb_coverage (scope, ecosystem, package, source_id, granted_at) VALUES (?, ?, ?, ?, ?)',
    );
    const grant = (scope: string, name: string | null) => {
      if (!exists.get(scope, ecosystem, name)) insert.run(scope, ecosystem, name, sourceId, now);
    };
    this.db.transaction(() => {
      if (!packages) grant('ECOSYSTEM', null);
      else for (const name of packages) grant('PACKAGE', normalizePackageName(ecosystem, name));
    })();
  }

  source(sourceId: string): SourceState | undefined {
    const row = this.db
      .prepare<
        [string],
        {
          source_id: string;
          kind: string;
          ecosystem: string | null;
          etag: string | null;
          cursor: string | null;
          synced_at: string | null;
          records: number;
        }
      >('SELECT * FROM kb_sources WHERE source_id = ?')
      .get(sourceId);
    if (!row) return undefined;
    return {
      sourceId: row.source_id,
      kind: row.kind,
      ...(row.ecosystem ? { ecosystem: row.ecosystem } : {}),
      ...(row.etag ? { etag: row.etag } : {}),
      ...(row.cursor ? { cursor: row.cursor } : {}),
      ...(row.synced_at ? { syncedAt: row.synced_at } : {}),
      records: row.records,
    };
  }

  saveSource(state: SourceState): void {
    this.db
      .prepare(
        `INSERT INTO kb_sources (source_id, kind, ecosystem, etag, cursor, synced_at, records) VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (source_id) DO UPDATE SET kind = excluded.kind, ecosystem = excluded.ecosystem, etag = excluded.etag,
           cursor = excluded.cursor, synced_at = excluded.synced_at, records = excluded.records`,
      )
      .run(
        state.sourceId,
        state.kind,
        state.ecosystem ?? null,
        state.etag ?? null,
        state.cursor ?? null,
        state.syncedAt ?? null,
        state.records,
      );
  }

  sources(): SourceState[] {
    return (
      this.db.prepare('SELECT source_id FROM kb_sources ORDER BY source_id').all() as Array<{ source_id: string }>
    ).map((r) => this.source(r.source_id) as SourceState);
  }

  /**
   * Freezes the current state. Returns the existing snapshot when nothing changed since it, so the
   * same knowledge always has the same snapshot id.
   */
  createSnapshot(): KbSnapshot {
    const watermark = (this.db.prepare('SELECT COALESCE(MAX(seq), 0) AS v FROM kb_revisions').get() as { v: number }).v;
    const coverageUpto = (this.db.prepare('SELECT COALESCE(MAX(id), 0) AS v FROM kb_coverage').get() as { v: number })
      .v;
    const intelUpto = (this.db.prepare('SELECT COALESCE(MAX(seq), 0) AS v FROM kb_intel').get() as { v: number }).v;
    const visible = this.visible(watermark);
    const intel = this.visibleIntel(intelUpto);
    const ecosystems = this.coveredEcosystems(coverageUpto);
    const coverage = this.db
      .prepare(
        'SELECT DISTINCT scope, ecosystem, package FROM kb_coverage WHERE id <= ? ORDER BY scope, ecosystem, package',
      )
      .all(coverageUpto);
    // The intelligence section is appended only when present, so snapshots taken before KEV/EPSS/NVD
    // were synced keep their ids.
    const intelSection = intel.length
      ? `\n--intel--\n${intel.map((r) => `${r.source}\u0000${r.key}\u0000${r.content_digest}`).join('\n')}`
      : '';
    const digest = sha256(
      `${visible.map((r) => `${r.record_id}\u0000${r.content_digest}`).join('\n')}\n--coverage--\n${stableStringify(coverage)}${intelSection}`,
    );
    const snapshotId = `kbs_${digest.slice('sha256:'.length, 'sha256:'.length + 16)}`;
    const existing = this.snapshot(snapshotId);
    if (existing) return existing;
    const snapshot: KbSnapshot = {
      snapshotId,
      watermark,
      coverageUpto,
      digest,
      recordCount: visible.filter((r) => !r.withdrawn).length,
      ecosystems,
      intelUpto,
      createdAt: new Date().toISOString(),
    };
    this.db
      .prepare(
        'INSERT INTO kb_snapshots (snapshot_id, watermark, coverage_upto, digest, record_count, ecosystems, intel_upto, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      )
      .run(
        snapshotId,
        watermark,
        coverageUpto,
        digest,
        snapshot.recordCount,
        JSON.stringify(ecosystems),
        intelUpto,
        snapshot.createdAt,
      );
    return snapshot;
  }

  snapshot(snapshotId: string): KbSnapshot | undefined {
    const row = this.db.prepare('SELECT * FROM kb_snapshots WHERE snapshot_id = ?').get(snapshotId) as
      | SnapshotRow
      | undefined;
    return row ? toSnapshot(row) : undefined;
  }

  latestSnapshot(): KbSnapshot | undefined {
    const row = this.db.prepare('SELECT * FROM kb_snapshots ORDER BY created_at DESC, rowid DESC LIMIT 1').get() as
      | SnapshotRow
      | undefined;
    return row ? toSnapshot(row) : undefined;
  }

  snapshots(): KbSnapshot[] {
    return (
      this.db.prepare('SELECT * FROM kb_snapshots ORDER BY created_at DESC, rowid DESC').all() as SnapshotRow[]
    ).map(toSnapshot);
  }

  /** Latest non-superseded revision per record at a watermark. */
  visible(watermark: number): VisibleRow[] {
    return this.db
      .prepare<[number], VisibleRow>(
        `SELECT r.record_id, r.content_digest, r.withdrawn, r.seq FROM kb_revisions r
         JOIN (SELECT record_id, MAX(seq) AS seq FROM kb_revisions WHERE seq <= ? GROUP BY record_id) m
           ON r.record_id = m.record_id AND r.seq = m.seq
         ORDER BY r.record_id`,
      )
      .all(watermark);
  }

  /** Advisory ids added or changed between two snapshots (ADR-007: drives NEW_ADVISORY causes). */
  diff(from: KbSnapshot, to: KbSnapshot): { added: Set<string>; modified: Set<string> } {
    const before = new Map(this.visible(from.watermark).map((r) => [r.record_id, r.content_digest]));
    const added = new Set<string>();
    const modified = new Set<string>();
    const current = this.visible(to.watermark);
    for (const row of current) {
      const prev = before.get(row.record_id);
      if (prev === undefined) added.add(row.record_id);
      else if (prev !== row.content_digest) modified.add(row.record_id);
    }
    // Intelligence that changes triage (newly in KEV, new NVD scoring) marks the advisories that alias
    // the CVE as updated. EPSS moves daily and is shown, not treated as a change cause.
    const changedCves = this.intelChangedCves(from.intelUpto, to.intelUpto);
    if (changedCves.size) {
      for (const row of current) {
        if (added.has(row.record_id) || modified.has(row.record_id)) continue;
        if (this.cvesOf(row.record_id, to).some((c) => changedCves.has(c))) modified.add(row.record_id);
      }
    }
    return { added, modified };
  }

  /** Stores one intelligence revision; returns false when identical to the latest one for the key. */
  ingestIntel(source: 'kev' | 'epss' | 'nvd', key: string, released: string, data: unknown): boolean {
    const canonical = stableStringify(data);
    const digest = sha256Hex(canonical);
    const latest = this.db
      .prepare<[string, string], { content_digest: string }>(
        'SELECT content_digest FROM kb_intel WHERE source = ? AND key = ? ORDER BY seq DESC LIMIT 1',
      )
      .get(source, key);
    if (latest?.content_digest === digest) return false;
    const result = this.db
      .prepare(
        'INSERT OR IGNORE INTO kb_intel (source, key, content_digest, released, data, ingested_at) VALUES (?, ?, ?, ?, ?, ?)',
      )
      .run(source, key, digest, released || null, gzipSync(canonical), new Date().toISOString());
    return result.changes > 0;
  }

  /** CVE ids referenced by any advisory (record id or alias); bounds what EPSS/NVD sync keeps. */
  referencedCves(): Set<string> {
    const rows = this.db
      .prepare(
        `SELECT record_id AS id FROM kb_revisions WHERE record_id LIKE 'CVE-%'
         UNION SELECT j.value AS id FROM kb_revisions r, json_each(r.aliases) j WHERE j.value LIKE 'CVE-%'`,
      )
      .all() as Array<{ id: string }>;
    return new Set(rows.map((r) => r.id));
  }

  /** Latest intelligence revision per (source, key) at a watermark. */
  visibleIntel(upto: number): Array<{ source: string; key: string; content_digest: string; seq: number }> {
    return this.db
      .prepare<[number], { source: string; key: string; content_digest: string; seq: number }>(
        `SELECT i.source, i.key, i.content_digest, i.seq FROM kb_intel i
         JOIN (SELECT source, key, MAX(seq) AS seq FROM kb_intel WHERE seq <= ? GROUP BY source, key) m
           ON i.source = m.source AND i.key = m.key AND i.seq = m.seq
         ORDER BY i.source, i.key`,
      )
      .all(upto);
  }

  /**
   * KEV / EPSS / CVSS for an advisory as of a snapshot, resolved through CVE aliases. Several ids of
   * one finding are merged: KEV if any CVE is listed, the highest EPSS and CVSS.
   */
  intelFor(snapshot: KbSnapshot, vulnerabilityIds: readonly string[]): VulnIntel | undefined {
    if (!snapshot.intelUpto) return undefined;
    const cves = new Set<string>();
    for (const id of vulnerabilityIds) {
      if (id.startsWith('CVE-')) cves.add(id);
      for (const c of this.cvesOf(id, snapshot)) cves.add(c);
    }
    if (cves.size === 0) return undefined;
    const kev = this.dataset<KevDataset>('kev', snapshot.intelUpto);
    const epss = this.dataset<EpssDataset>('epss', snapshot.intelUpto);
    const intel: VulnIntel = { cves: [...cves].sort() };
    const cwes = new Set<string>();
    for (const cve of intel.cves) {
      const k = kev?.entries[cve];
      if (k && (!intel.kev || k.dateAdded < intel.kev.dateAdded)) {
        intel.kev = {
          dateAdded: k.dateAdded,
          ...(k.dueDate ? { dueDate: k.dueDate } : {}),
          ransomware: k.ransomware,
          catalogVersion: kev.catalogVersion,
        };
      }
      const e = epss?.scores[cve];
      if (e && (!intel.epss || e[0] > intel.epss.score))
        intel.epss = { score: e[0], percentile: e[1], date: epss.scoreDate };
      const nvd = this.intelRecord<NvdRecord>('nvd', cve, snapshot.intelUpto);
      if (nvd?.cvss && (!intel.cvss || nvd.cvss.baseScore > intel.cvss.baseScore)) intel.cvss = nvd.cvss;
      for (const c of nvd?.cwes ?? []) cwes.add(c);
    }
    if (cwes.size) intel.cwes = [...cwes].sort();
    return intel.kev || intel.epss || intel.cvss ? intel : undefined;
  }

  private cvesOf(id: string, snapshot: KbSnapshot): string[] {
    const hit = this.lookup(id, snapshot);
    if (!hit) return id.startsWith('CVE-') ? [id] : [];
    return [hit.record.id, ...(hit.record.aliases ?? [])].filter((a) => a.startsWith('CVE-'));
  }

  private intelChangedCves(fromUpto: number, toUpto: number): Set<string> {
    const changed = new Set<string>();
    if (toUpto <= fromUpto) return changed;
    const before = this.dataset<KevDataset>('kev', fromUpto);
    const after = this.dataset<KevDataset>('kev', toUpto);
    for (const cve of Object.keys(after?.entries ?? {})) if (!before?.entries[cve]) changed.add(cve);
    const nvd = this.db
      .prepare<[number, number], { key: string }>(
        "SELECT DISTINCT key FROM kb_intel WHERE source = 'nvd' AND seq > ? AND seq <= ?",
      )
      .all(fromUpto, toUpto);
    for (const row of nvd) changed.add(row.key);
    return changed;
  }

  private readonly datasetCache = new Map<number, unknown>();

  private dataset<T>(source: 'kev' | 'epss', upto: number): T | undefined {
    const row = this.db
      .prepare<[string, number], { seq: number }>(
        "SELECT MAX(seq) AS seq FROM kb_intel WHERE source = ? AND key = '*' AND seq <= ?",
      )
      .get(source, upto);
    if (!row?.seq) return undefined;
    if (!this.datasetCache.has(row.seq)) this.datasetCache.set(row.seq, this.intelRecord<T>(source, '*', upto));
    return this.datasetCache.get(row.seq) as T | undefined;
  }

  private intelRecord<T>(source: string, key: string, upto: number): T | undefined {
    const row = this.db
      .prepare<[string, string, number], { data: Buffer }>(
        'SELECT data FROM kb_intel WHERE source = ? AND key = ? AND seq <= ? ORDER BY seq DESC LIMIT 1',
      )
      .get(source, key, upto);
    return row ? (JSON.parse(gunzipSync(row.data).toString()) as T) : undefined;
  }

  coveredEcosystems(coverageUpto: number): string[] {
    return (
      this.db
        .prepare("SELECT DISTINCT ecosystem FROM kb_coverage WHERE scope = 'ECOSYSTEM' AND id <= ? ORDER BY ecosystem")
        .all(coverageUpto) as Array<{ ecosystem: string }>
    ).map((r) => r.ecosystem);
  }

  covers(snapshot: KbSnapshot, ecosystem: string, name: string): boolean {
    if (snapshot.ecosystems.includes(ecosystem)) return true;
    return (
      this.db
        .prepare(
          "SELECT 1 FROM kb_coverage WHERE scope = 'PACKAGE' AND ecosystem = ? AND package = ? AND id <= ? LIMIT 1",
        )
        .get(ecosystem, normalizePackageName(ecosystem, name), snapshot.coverageUpto) !== undefined
    );
  }

  /** Records visible in a snapshot that affect an ecosystem (withdrawn records excluded). */
  *recordsFor(snapshot: KbSnapshot, ecosystem: string): Generator<{ id: string; json: Buffer }> {
    const latestSeqs = this.db
      .prepare<[number, string], { record_id: string; seq: number }>(
        `SELECT m.record_id, m.seq FROM (SELECT record_id, MAX(seq) AS seq FROM kb_revisions WHERE seq <= ? GROUP BY record_id) m
         WHERE EXISTS (SELECT 1 FROM kb_affected a WHERE a.seq = m.seq AND a.ecosystem = ?) ORDER BY m.record_id`,
      )
      .iterate(snapshot.watermark, ecosystem);
    const raw = this.db.prepare<[number], { raw: Buffer; withdrawn: string | null }>(
      'SELECT raw, withdrawn FROM kb_revisions WHERE seq = ?',
    );
    for (const row of latestSeqs) {
      const rev = raw.get(row.seq);
      if (!rev || rev.withdrawn) continue;
      yield { id: row.record_id, json: gunzipSync(rev.raw) };
    }
  }

  ecosystemsWithRecords(snapshot: KbSnapshot): string[] {
    return (
      this.db
        .prepare('SELECT DISTINCT ecosystem FROM kb_affected WHERE seq <= ? ORDER BY ecosystem')
        .all(snapshot.watermark) as Array<{ ecosystem: string }>
    ).map((r) => r.ecosystem);
  }

  /** Record as of a snapshot (or latest), matched by id or alias. */
  lookup(id: string, snapshot?: KbSnapshot): { record: OsvRecord; seq: number; sourceId: string } | undefined {
    const watermark = snapshot?.watermark ?? Number.MAX_SAFE_INTEGER;
    const direct = this.db
      .prepare<[string, number], { raw: Buffer; seq: number; source_id: string }>(
        'SELECT raw, seq, source_id FROM kb_revisions WHERE record_id = ? AND seq <= ? ORDER BY seq DESC LIMIT 1',
      )
      .get(id, watermark);
    const row =
      direct ??
      this.db
        .prepare<[number, string], { raw: Buffer; seq: number; source_id: string }>(
          `SELECT raw, seq, source_id FROM kb_revisions WHERE seq <= ? AND EXISTS (SELECT 1 FROM json_each(aliases) WHERE value = ?)
           ORDER BY seq DESC LIMIT 1`,
        )
        .get(watermark, id);
    if (!row) return undefined;
    return {
      record: OsvRecord.parse(JSON.parse(gunzipSync(row.raw).toString())),
      seq: row.seq,
      sourceId: row.source_id,
    };
  }

  latestModified(recordId: string): string | undefined {
    const row = this.db
      .prepare<[string], { modified: string | null }>(
        'SELECT modified FROM kb_revisions WHERE record_id = ? ORDER BY seq DESC LIMIT 1',
      )
      .get(recordId);
    return row?.modified ?? undefined;
  }

  /** Packages granted coverage by a source (used to refresh package-scoped syncs). */
  coveredPackages(sourceId: string): Array<{ ecosystem: string; name: string }> {
    return this.db
      .prepare<[string], { ecosystem: string; package: string }>(
        "SELECT DISTINCT ecosystem, package FROM kb_coverage WHERE scope = 'PACKAGE' AND source_id = ? ORDER BY ecosystem, package",
      )
      .all(sourceId)
      .map((r) => ({ ecosystem: r.ecosystem, name: r.package }));
  }

  stats(): { revisions: number; records: number; snapshots: number; intelRevisions: number } {
    const get = (sql: string) => (this.db.prepare(sql).get() as { v: number }).v;
    return {
      revisions: get('SELECT COUNT(*) AS v FROM kb_revisions'),
      records: get('SELECT COUNT(DISTINCT record_id) AS v FROM kb_revisions'),
      snapshots: get('SELECT COUNT(*) AS v FROM kb_snapshots'),
      intelRevisions: get('SELECT COUNT(*) AS v FROM kb_intel'),
    };
  }
}

interface SnapshotRow {
  snapshot_id: string;
  watermark: number;
  coverage_upto: number;
  digest: string;
  record_count: number;
  ecosystems: string;
  intel_upto: number;
  created_at: string;
}

function toSnapshot(row: SnapshotRow): KbSnapshot {
  return {
    snapshotId: row.snapshot_id,
    watermark: row.watermark,
    coverageUpto: row.coverage_upto,
    digest: row.digest as Digest,
    recordCount: row.record_count,
    ecosystems: JSON.parse(row.ecosystems) as string[],
    intelUpto: row.intel_upto ?? 0,
    createdAt: row.created_at,
  };
}
