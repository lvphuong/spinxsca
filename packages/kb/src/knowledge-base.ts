import { join } from 'node:path';
import type { AdvisoryInfo, KnowledgeBasePort, KnowledgeBaseRef } from '@spinxsca/core';
import type { VulnIntel } from '@spinxsca/schemas';
import { materializeOsvScannerDb } from './materialize';
import { affectedPackages, fixedVersions, type OsvRecord } from './osv';
import { type KbSnapshot, KbStore } from './store';

/**
 * Local knowledge base facade: the core port (snapshots, diffs) plus what dependency scanners need
 * (materialized offline databases and coverage checks).
 */
export class LocalKnowledgeBase implements KnowledgeBasePort {
  private constructor(
    readonly store: KbStore,
    readonly cacheRoot: string,
  ) {}

  static open(dir: string): LocalKnowledgeBase {
    return new LocalKnowledgeBase(KbStore.open(dir), join(dir, 'materialized'));
  }

  close(): void {
    this.store.close();
  }

  /**
   * Advisories as of a snapshot for the agent's `kb_lookup` (ADR-043): affected packages with fixed
   * versions, KEV/EPSS and the vulnerable symbols the record names, if any.
   */
  async advisories(snapshotId: string | undefined, ids: readonly string[]): Promise<AdvisoryInfo[]> {
    const snapshot = snapshotId ? this.store.snapshot(snapshotId) : this.store.latestSnapshot();
    const out: AdvisoryInfo[] = [];
    for (const id of ids) {
      const found = this.store.lookup(id, snapshot);
      if (!found) continue;
      const record = found.record;
      const intel = snapshot ? this.store.intelFor(snapshot, [record.id, ...(record.aliases ?? [])]) : undefined;
      out.push({
        id: record.id,
        aliases: record.aliases ?? [],
        summary: (record.summary ?? record.details ?? '').slice(0, 1500),
        ...(record.database_specific?.severity ? { severity: record.database_specific.severity } : {}),
        packages: affectedPackages(record).map((p) => ({ ...p, fixed: fixedVersions(record, p.ecosystem, p.name) })),
        symbols: symbolsOf(record),
        ...(intel?.kev ? { kev: { dateAdded: intel.kev.dateAdded } } : {}),
        ...(intel?.epss ? { epss: { score: intel.epss.score, percentile: intel.epss.percentile } } : {}),
        references: ((record as { references?: Array<{ url?: string }> }).references ?? [])
          .map((r) => r.url ?? '')
          .filter(Boolean)
          .slice(0, 10),
      });
    }
    return out;
  }

  async resolveSnapshot(snapshotId?: string): Promise<KnowledgeBaseRef | null> {
    const snapshot = snapshotId ? this.store.snapshot(snapshotId) : this.store.latestSnapshot();
    return snapshot ? toRef(snapshot) : null;
  }

  async diff(
    fromSnapshotId: string,
    toSnapshotId: string,
  ): Promise<{ added: ReadonlySet<string>; modified: ReadonlySet<string> }> {
    const from = this.store.snapshot(fromSnapshotId);
    const to = this.store.snapshot(toSnapshotId);
    if (!from || !to) return { added: new Set(), modified: new Set() };
    return this.store.diff(from, to);
  }

  async intel(snapshotId: string, vulnerabilityIds: readonly string[]): Promise<VulnIntel | undefined> {
    const snapshot = this.store.snapshot(snapshotId);
    return snapshot ? this.store.intelFor(snapshot, vulnerabilityIds) : undefined;
  }

  /** Packages named by advisories added or changed between two snapshots (drives reassessment). */
  async changedPackages(
    fromSnapshotId: string | undefined,
    toSnapshotId: string,
  ): Promise<Array<{ ecosystem: string; name: string; advisory: string }>> {
    const to = this.require(toSnapshotId);
    const from = fromSnapshotId ? this.store.snapshot(fromSnapshotId) : undefined;
    const changed = from
      ? this.store.diff(from, to)
      : { added: new Set(this.store.visible(to.watermark).map((r) => r.record_id)), modified: new Set<string>() };
    const out: Array<{ ecosystem: string; name: string; advisory: string }> = [];
    for (const id of [...changed.added, ...changed.modified]) {
      const hit = this.store.lookup(id, to);
      if (!hit) continue;
      for (const pkg of affectedPackages(hit.record)) out.push({ ...pkg, advisory: id });
    }
    return out;
  }

  async materialize(snapshotId: string, ecosystems: readonly string[]): Promise<string> {
    return materializeOsvScannerDb(this.store, this.require(snapshotId), ecosystems, this.cacheRoot);
  }

  async covers(snapshotId: string, ecosystem: string, name: string): Promise<boolean> {
    return this.store.covers(this.require(snapshotId), ecosystem, name);
  }

  private require(snapshotId: string): KbSnapshot {
    const snapshot = this.store.snapshot(snapshotId);
    if (!snapshot) throw new Error(`knowledge base snapshot ${snapshotId} not found`);
    return snapshot;
  }
}

function toRef(snapshot: KbSnapshot): KnowledgeBaseRef {
  return { snapshotId: snapshot.snapshotId, digest: snapshot.digest, ecosystems: snapshot.ecosystems };
}

/** Vulnerable symbols named by an OSV record (Go `imports[].symbols`, `affected_functions` variants). */
export function symbolsOf(record: OsvRecord): string[] {
  const out = new Set<string>();
  for (const a of record.affected ?? []) {
    const eco = (a as { ecosystem_specific?: Record<string, unknown> }).ecosystem_specific ?? {};
    const db = (a as { database_specific?: Record<string, unknown> }).database_specific ?? {};
    for (const imp of (eco.imports as Array<{ symbols?: string[] }> | undefined) ?? [])
      for (const s of imp.symbols ?? []) out.add(s);
    for (const source of [eco.affected_functions, db.affected_functions, eco.functions]) {
      if (Array.isArray(source)) for (const s of source) if (typeof s === 'string') out.add(s);
    }
  }
  return [...out].sort();
}
