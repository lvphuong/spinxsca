import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  sign,
  verify,
} from 'node:crypto';
import { gunzipSync, gzipSync } from 'node:zlib';
import { stableStringify } from '@spinxsca/core';
import type { KbSnapshot, KbStore } from './store';

/**
 * Offline knowledge base bundle (docs/architecture/06 section 3.4, ADR-037): everything visible in one
 * snapshot (advisory revisions, coverage grants, intelligence), signed with Ed25519. Importing it into
 * a store fed only by bundles reproduces the same content-addressed snapshot id, which the importer
 * checks, so an on-prem server or a remote worker scans against exactly the control plane's data.
 */
export const BUNDLE_FORMAT = 'spinxsca-kb-bundle/v1';
const MAGIC = Buffer.from(`${BUNDLE_FORMAT}\n`);

export interface BundleHeader {
  format: typeof BUNDLE_FORMAT;
  snapshotId: string;
  digest: string;
  createdAt: string;
  records: number;
  coverage: number;
  intel: number;
  payloadSha256: string;
  keyId: string;
}

export interface SigningKey {
  privateKeyPem: string;
  publicKeyPem: string;
  keyId: string;
}

type Line =
  | { t: 'rev'; sourceId: string; raw: string }
  | { t: 'cov'; scope: string; ecosystem: string; package: string | null; sourceId: string }
  | { t: 'intel'; source: 'kev' | 'epss' | 'nvd'; key: string; released: string | null; data: string };

/** Key id: first 16 hex characters of the SHA-256 of the DER public key. */
export function keyIdOf(publicKey: KeyObject | string): string {
  const key = typeof publicKey === 'string' ? createPublicKey(publicKey) : publicKey;
  return createHash('sha256')
    .update(key.export({ type: 'spki', format: 'der' }))
    .digest('hex')
    .slice(0, 16);
}

export function generateSigningKey(): SigningKey {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    keyId: keyIdOf(publicKey),
  };
}

export function exportBundle(store: KbStore, snapshot: KbSnapshot, privateKeyPem: string): Buffer {
  const lines: Line[] = [];
  const rev = store.db.prepare<[number], { raw: Buffer; source_id: string }>(
    'SELECT raw, source_id FROM kb_revisions WHERE seq = ?',
  );
  for (const row of store.visible(snapshot.watermark)) {
    const r = rev.get(row.seq);
    if (r) lines.push({ t: 'rev', sourceId: r.source_id, raw: r.raw.toString('base64') });
  }
  const coverage = store.db
    .prepare(
      'SELECT scope, ecosystem, package, MIN(source_id) AS source_id FROM kb_coverage WHERE id <= ? GROUP BY scope, ecosystem, package ORDER BY scope, ecosystem, package',
    )
    .all(snapshot.coverageUpto) as Array<{
    scope: string;
    ecosystem: string;
    package: string | null;
    source_id: string;
  }>;
  for (const c of coverage)
    lines.push({ t: 'cov', scope: c.scope, ecosystem: c.ecosystem, package: c.package, sourceId: c.source_id });
  const intel = store.db.prepare<[number], { released: string | null; data: Buffer }>(
    'SELECT released, data FROM kb_intel WHERE seq = ?',
  );
  for (const row of store.visibleIntel(snapshot.intelUpto)) {
    const i = intel.get(row.seq);
    if (i)
      lines.push({
        t: 'intel',
        source: row.source as 'kev' | 'epss' | 'nvd',
        key: row.key,
        released: i.released,
        data: i.data.toString('base64'),
      });
  }
  const payload = gzipSync(`${lines.map((l) => JSON.stringify(l)).join('\n')}\n`);
  const privateKey = createPrivateKey(privateKeyPem);
  const header: BundleHeader = {
    format: BUNDLE_FORMAT,
    snapshotId: snapshot.snapshotId,
    digest: snapshot.digest,
    createdAt: snapshot.createdAt,
    records: lines.filter((l) => l.t === 'rev').length,
    coverage: coverage.length,
    intel: lines.filter((l) => l.t === 'intel').length,
    payloadSha256: createHash('sha256').update(payload).digest('hex'),
    keyId: keyIdOf(createPublicKey(privateKey)),
  };
  const headerText = stableStringify(header);
  const signature = sign(null, Buffer.from(headerText), privateKey).toString('base64');
  return Buffer.concat([MAGIC, Buffer.from(`${headerText}\n${signature}\n`), payload]);
}

/** Parses and verifies a bundle against trusted public keys; throws on any mismatch. */
export function readBundle(
  bundle: Uint8Array,
  trustedPublicKeys: readonly string[],
): { header: BundleHeader; lines: Line[] } {
  const buf = Buffer.from(bundle);
  if (!buf.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error('not a spinxsca knowledge base bundle');
  const headerEnd = buf.indexOf(0x0a, MAGIC.length);
  const sigEnd = buf.indexOf(0x0a, headerEnd + 1);
  if (headerEnd < 0 || sigEnd < 0) throw new Error('truncated bundle');
  const headerText = buf.subarray(MAGIC.length, headerEnd).toString();
  const signature = Buffer.from(buf.subarray(headerEnd + 1, sigEnd).toString(), 'base64');
  const payload = buf.subarray(sigEnd + 1);
  const header = JSON.parse(headerText) as BundleHeader;
  if (header.format !== BUNDLE_FORMAT) throw new Error(`unsupported bundle format ${header.format}`);
  const key = trustedPublicKeys.map((pem) => createPublicKey(pem)).find((k) => keyIdOf(k) === header.keyId);
  if (!key) throw new Error(`bundle signed by untrusted key ${header.keyId}`);
  if (stableStringify(header) !== headerText || !verify(null, Buffer.from(headerText), key, signature)) {
    throw new Error('bundle signature is invalid');
  }
  if (createHash('sha256').update(payload).digest('hex') !== header.payloadSha256)
    throw new Error('bundle payload does not match its signed digest');
  const lines = gunzipSync(payload)
    .toString()
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Line);
  return { header, lines };
}

/**
 * Imports a verified bundle. The resulting snapshot must equal the bundle's: a store that also holds
 * data from other sources cannot reproduce it, and the import fails instead of scanning against a
 * different knowledge base.
 */
export function importBundle(
  store: KbStore,
  bundle: Uint8Array,
  trustedPublicKeys: readonly string[],
): { snapshot: KbSnapshot; header: BundleHeader; added: number } {
  const { header, lines } = readBundle(bundle, trustedPublicKeys);
  const existing = store.snapshot(header.snapshotId);
  if (existing) return { snapshot: existing, header, added: 0 };
  let added = 0;
  const bySource = new Map<string, unknown[]>();
  for (const line of lines) {
    if (line.t !== 'rev') continue;
    const records = bySource.get(line.sourceId) ?? [];
    records.push(JSON.parse(gunzipSync(Buffer.from(line.raw, 'base64')).toString()));
    bySource.set(line.sourceId, records);
  }
  for (const [sourceId, records] of bySource) {
    const stats = store.ingest(sourceId, records);
    added += stats.added + stats.updated;
  }
  for (const line of lines) {
    if (line.t === 'cov')
      store.grantCoverage(
        line.sourceId,
        line.ecosystem,
        line.scope === 'PACKAGE' && line.package ? [line.package] : undefined,
      );
    if (line.t === 'intel') {
      store.ingestIntel(
        line.source,
        line.key,
        line.released ?? '',
        JSON.parse(gunzipSync(Buffer.from(line.data, 'base64')).toString()),
      );
    }
  }
  const snapshot = store.createSnapshot();
  if (snapshot.snapshotId !== header.snapshotId) {
    throw new Error(
      `imported data produced snapshot ${snapshot.snapshotId}, not ${header.snapshotId}: this knowledge base also holds data from other sources; use a directory fed only by bundles`,
    );
  }
  store.saveSource({
    sourceId: 'bundle',
    kind: 'bundle',
    cursor: header.snapshotId,
    syncedAt: new Date().toISOString(),
    records: header.records,
  });
  return { snapshot, header, added };
}
