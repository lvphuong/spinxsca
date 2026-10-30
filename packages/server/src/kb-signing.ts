import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { exportBundle, generateSigningKey, keyIdOf, LocalKnowledgeBase, type SigningKey } from '@spinxsca/kb';

/** The control plane's Ed25519 key for knowledge base bundles, created on first use (private key 0600). */
export function loadSigningKey(dataDir: string): SigningKey {
  const privatePath = join(dataDir, 'kb-signing.key');
  const publicPath = join(dataDir, 'kb-signing.pub');
  if (existsSync(privatePath) && existsSync(publicPath)) {
    const publicKeyPem = readFileSync(publicPath, 'utf8');
    return { privateKeyPem: readFileSync(privatePath, 'utf8'), publicKeyPem, keyId: keyIdOf(publicKeyPem) };
  }
  mkdirSync(dataDir, { recursive: true });
  const key = generateSigningKey();
  writeFileSync(privatePath, key.privateKeyPem, { mode: 0o600 });
  chmodSync(privatePath, 0o600);
  writeFileSync(publicPath, key.publicKeyPem);
  return key;
}

/** Signed bundle of a snapshot (latest by default), cached per snapshot id. */
export function snapshotBundle(
  kbDir: string,
  cacheDir: string,
  key: SigningKey,
  snapshotId?: string,
): { snapshotId: string; bundle: Buffer } | undefined {
  const kb = LocalKnowledgeBase.open(kbDir);
  try {
    const snapshot = snapshotId ? kb.store.snapshot(snapshotId) : kb.store.latestSnapshot();
    if (!snapshot) return undefined;
    const path = join(cacheDir, `${snapshot.snapshotId}.${key.keyId}.bundle`);
    if (existsSync(path)) return { snapshotId: snapshot.snapshotId, bundle: readFileSync(path) };
    const bundle = exportBundle(kb.store, snapshot, key.privateKeyPem);
    mkdirSync(cacheDir, { recursive: true });
    writeFileSync(path, bundle);
    return { snapshotId: snapshot.snapshotId, bundle };
  } finally {
    kb.close();
  }
}
