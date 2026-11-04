import { type Digest, GENESIS_HASH } from '@spinxsca/schemas';
import { sha256, stableStringify } from '../ids';

export interface Chained {
  seq: number;
  prevHash: string;
  hash: string;
}

/** hash = sha256(prevHash ‖ canonical JSON of the record without its links). */
export function chainHash(prevHash: string, body: object): Digest {
  return sha256(`${prevHash}\n${stableStringify(body)}`);
}

function bodyOf(record: object): Record<string, unknown> {
  const { hash: _hash, prevHash: _prev, ...body } = record as Record<string, unknown>;
  return body;
}

/** Appends `body` after `prev` (or at the genesis) and returns the linked record. */
export function link<T extends object>(prev: Pick<Chained, 'seq' | 'hash'> | undefined, body: T): T & Chained {
  const seq = prev ? prev.seq + 1 : 0;
  const prevHash = prev ? prev.hash : GENESIS_HASH;
  const withSeq = { ...body, seq };
  return { ...withSeq, prevHash, hash: chainHash(prevHash, bodyOf(withSeq)) };
}

export type ChainVerification = { ok: true; length: number; head: string } | { ok: false; seq: number; reason: string };

/**
 * Verifies a chain in sequence order. Tamper-evident only: whoever can rewrite every record can
 * rebuild the chain, so heads are also anchored outside the case store (registry audit, reports).
 */
export function verifyChain(records: readonly (Chained & object)[]): ChainVerification {
  let prevHash = GENESIS_HASH;
  for (let i = 0; i < records.length; i++) {
    const r = records[i] as Chained;
    if (r.seq !== i) return { ok: false, seq: r.seq, reason: `expected seq ${i}` };
    if (r.prevHash !== prevHash) return { ok: false, seq: r.seq, reason: 'broken link to the previous record' };
    if (chainHash(prevHash, bodyOf(r)) !== r.hash) return { ok: false, seq: r.seq, reason: 'record content changed' };
    prevHash = r.hash;
  }
  return { ok: true, length: records.length, head: prevHash };
}
