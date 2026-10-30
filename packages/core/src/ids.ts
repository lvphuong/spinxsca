import { createHash, randomBytes } from 'node:crypto';
import type { Digest } from '@spinxsca/schemas';

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** ULID: 48-bit millisecond timestamp + 80 random bits, Crockford base32. Lexicographically sortable. */
export function ulid(now: number = Date.now()): string {
  let time = '';
  let t = now;
  for (let i = 0; i < 10; i++) {
    time = CROCKFORD[t % 32] + time;
    t = Math.floor(t / 32);
  }
  const bytes = randomBytes(10);
  let bits = 0n;
  for (const byte of bytes) bits = (bits << 8n) | BigInt(byte);
  let random = '';
  for (let i = 0; i < 16; i++) {
    random = CROCKFORD[Number(bits & 31n)] + random;
    bits >>= 5n;
  }
  return time + random;
}

export function newId(prefix: string): string {
  return `${prefix}_${ulid().toLowerCase()}`;
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

export function sha256(data: string | Uint8Array): Digest {
  return `sha256:${sha256Hex(data)}`;
}

/** JSON serialization with recursively sorted object keys, so equal values produce equal digests. */
export function stableStringify(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = sortKeys(v);
    }
    return out;
  }
  return value;
}

export function digestOf(value: unknown): Digest {
  return sha256(stableStringify(value));
}

/** Repository-relative POSIX path without leading "./" or "/". */
export function normalizeRelPath(path: string): string {
  return path
    .replace(/\\/g, '/')
    .replace(/^(\.\/)+/, '')
    .replace(/^\/+/, '');
}
