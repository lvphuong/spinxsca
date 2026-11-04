import { GENESIS_HASH } from '@spinxsca/schemas';
import { describe, expect, it } from 'vitest';
import { type Chained, link, MemoryAuditSink, verifyChain } from '../src/index';

type Rec = { caseId: string; stage: string; data: unknown } & Chained;

describe('hash chain', () => {
  const build = () => {
    const out: Rec[] = [];
    let prev: Rec | undefined;
    for (let i = 0; i < 5; i++) {
      prev = link(prev, { caseId: 'c', stage: 'tool.finished', data: { i } as unknown });
      out.push(prev);
    }
    return out;
  };

  it('links records from the genesis and verifies', () => {
    const chain = build();
    expect(chain[0]?.prevHash).toBe(GENESIS_HASH);
    expect(verifyChain(chain)).toMatchObject({ ok: true, length: 5, head: chain[4]?.hash });
  });

  it('detects edits, deletions and reordering', () => {
    const edited = build();
    (edited[2] as Rec).data = { i: 99 };
    expect(verifyChain(edited)).toMatchObject({ ok: false, seq: 2 });
    const deleted = build();
    deleted.splice(1, 1);
    expect(verifyChain(deleted).ok).toBe(false);
    const swapped = build();
    [swapped[1], swapped[2]] = [swapped[2] as Rec, swapped[1] as Rec];
    expect(verifyChain(swapped).ok).toBe(false);
  });

  it('keeps one chain per case in the memory audit sink', async () => {
    const sink = new MemoryAuditSink();
    await sink.append({ caseId: 'a', stage: 'case.started', actor: 'host', data: {} });
    await sink.append({ caseId: 'b', stage: 'case.started', actor: 'host', data: {} });
    await sink.append({ caseId: 'a', stage: 'case.stopped', actor: 'host', data: {} });
    expect(verifyChain(sink.forCase('a'))).toMatchObject({ ok: true, length: 2 });
    expect(verifyChain(sink.forCase('b'))).toMatchObject({ ok: true, length: 1 });
  });
});
