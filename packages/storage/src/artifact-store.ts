import { mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { type ArtifactStore, sha256Hex } from '@spinxsca/core';
import type { ArtifactRef, Digest } from '@spinxsca/schemas';

/** Content-addressed artifact directory: <root>/<hex[0:2]>/<hex>. Writes are atomic and idempotent. */
export class FsArtifactStore implements ArtifactStore {
  constructor(readonly root: string) {}

  async put(data: string | Uint8Array, mediaType: string): Promise<ArtifactRef> {
    const bytes = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    const hex = sha256Hex(bytes);
    const path = this.pathFor(hex);
    try {
      await stat(path);
    } catch {
      await mkdir(join(this.root, hex.slice(0, 2)), { recursive: true });
      const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
      await writeFile(tmp, bytes);
      await rename(tmp, path);
    }
    return { digest: `sha256:${hex}`, mediaType, size: bytes.byteLength };
  }

  async get(digest: Digest): Promise<Uint8Array> {
    return readFile(this.pathFor(hexOf(digest)));
  }

  async getText(digest: Digest): Promise<string> {
    return (await this.get(digest)).toString();
  }

  async has(digest: Digest): Promise<boolean> {
    try {
      await stat(this.pathFor(hexOf(digest)));
      return true;
    } catch {
      return false;
    }
  }

  pathFor(hex: string): string {
    return join(this.root, hex.slice(0, 2), hex);
  }
}

function hexOf(digest: Digest): string {
  const hex = digest.slice('sha256:'.length);
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`invalid digest ${digest}`);
  return hex;
}
