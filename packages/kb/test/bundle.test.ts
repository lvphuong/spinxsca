import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  exportBundle,
  generateSigningKey,
  importBundle,
  importOsvFiles,
  KbStore,
  readBundle,
  syncKev,
} from '../src/index';

const FIXTURES = resolve(__dirname, '../../../evals/fixtures/osv');
let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'spx-bundle-'));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

const kev = (cves: string[]) =>
  (async () =>
    new Response(
      JSON.stringify({
        catalogVersion: 'v1',
        dateReleased: '2026-10-30T00:00:00Z',
        vulnerabilities: cves.map((cveID) => ({ cveID, dateAdded: '2026-10-30' })),
      }),
    )) as unknown as typeof fetch;

describe('signed knowledge base bundles', () => {
  it('reproduces the exact snapshot on another store and rejects tampering or untrusted keys', async () => {
    const key = generateSigningKey();
    const source = KbStore.open(join(dir, 'source'));
    importOsvFiles(source, [join(FIXTURES, 'npm')], { authoritativeFor: ['npm'] });
    importOsvFiles(source, [join(FIXTURES, 'PyPI')]);
    source.grantCoverage('osv:api', 'PyPI', ['Jinja2']);
    await syncKev(source, { fetch: kev(['CVE-2020-28500']) });
    const snapshot = source.createSnapshot();
    const bundle = exportBundle(source, snapshot, key.privateKeyPem);

    const replica = KbStore.open(join(dir, 'replica'));
    const imported = importBundle(replica, bundle, [key.publicKeyPem]);
    expect(imported.snapshot.snapshotId).toBe(snapshot.snapshotId);
    expect(imported.header).toMatchObject({ records: snapshot.recordCount, intel: 1 });
    expect(replica.intelFor(imported.snapshot, ['GHSA-29mw-wpgm-hmr9'])?.kev?.catalogVersion).toBe('v1');
    expect(replica.covers(imported.snapshot, 'npm', 'lodash')).toBe(true);
    // Idempotent re-import.
    expect(importBundle(replica, bundle, [key.publicKeyPem]).added).toBe(0);

    // A later snapshot on top of an earlier one: the replica's diff still works.
    await syncKev(source, { fetch: kev(['CVE-2020-28500', 'CVE-2021-23337']) });
    const next = source.createSnapshot();
    const second = importBundle(replica, exportBundle(source, next, key.privateKeyPem), [key.publicKeyPem]);
    expect(second.snapshot.snapshotId).toBe(next.snapshotId);
    expect(replica.diff(imported.snapshot, second.snapshot).modified).toEqual(new Set(['GHSA-35jh-r3h4-6jhm']));

    const other = generateSigningKey();
    expect(() => readBundle(bundle, [other.publicKeyPem])).toThrow('untrusted key');
    const tampered = Buffer.from(bundle);
    tampered.writeUInt8((tampered.readUInt8(tampered.length - 5) ^ 0xff) & 0xff, tampered.length - 5);
    expect(() => readBundle(tampered, [key.publicKeyPem])).toThrow('payload does not match');
    const forgedHeader = Buffer.from(
      bundle.toString('latin1').replace(`"records":${snapshot.recordCount}`, '"records":1'),
      'latin1',
    );
    expect(() => readBundle(forgedHeader, [key.publicKeyPem])).toThrow('signature is invalid');

    // A store with foreign data cannot reproduce the snapshot.
    const mixed = KbStore.open(join(dir, 'mixed'));
    importOsvFiles(mixed, [join(FIXTURES, 'Maven')]);
    expect(() => importBundle(mixed, bundle, [key.publicKeyPem])).toThrow('other sources');
    for (const s of [source, replica, mixed]) s.close();
  });
});
