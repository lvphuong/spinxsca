import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyChain } from '@spinxsca/core';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { FsArtifactStore, migrate, SqliteScanRepository } from '../src/index';
import { caseRepositoryContract } from './case-contract';
import { repositoryContract } from './contract';

const digest = (c: string) => `sha256:${c.repeat(64)}` as const;
let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'spx-storage-'));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe('SqliteScanRepository', () => {
  it('applies migrations once', () => {
    const sqlite = new Database(':memory:');
    expect(migrate(sqlite)).toEqual(['0000_init', '0001_agent_runs', '0002_autonomy']);
    expect(migrate(sqlite)).toEqual([]);
    sqlite.close();
  });
});

repositoryContract('sqlite', async () => {
  const repo = SqliteScanRepository.open(join(dir, 'state.db'));
  return { repo, close: () => repo.close() };
});

caseRepositoryContract('sqlite', async () => {
  const scans = SqliteScanRepository.open(join(dir, 'state.db'));
  return { repo: scans.cases(), close: () => scans.close() };
});

describe('case store tamper evidence (sqlite)', () => {
  it('detects a journal row edited in place', async () => {
    const path = join(dir, 'state.db');
    const scans = SqliteScanRepository.open(path);
    const cases = scans.cases();
    for (let i = 0; i < 3; i++) {
      await cases.appendJournal({ caseId: 'c', kind: 'NOTE', author: 'host', handles: [], refs: [], text: `n${i}` });
    }
    scans.close();
    const raw = new Database(path);
    const row = raw.prepare('SELECT data FROM case_journal WHERE case_id = ? AND seq = 1').get('c') as { data: string };
    raw
      .prepare('UPDATE case_journal SET data = ? WHERE case_id = ? AND seq = 1')
      .run(JSON.stringify({ ...JSON.parse(row.data), text: 'rewritten' }), 'c');
    raw.close();
    const reopened = SqliteScanRepository.open(path);
    expect(verifyChain(await reopened.cases().listJournal('c'))).toMatchObject({ ok: false, seq: 1 });
    reopened.close();
  });
});

describe('FsArtifactStore', () => {
  it('stores content by digest idempotently', async () => {
    const store = new FsArtifactStore(join(dir, 'artifacts'));
    const a = await store.put('hello', 'text/plain');
    const b = await store.put('hello', 'text/plain');
    expect(a.digest).toBe(b.digest);
    expect(a.digest).toBe('sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    expect(await store.getText(a.digest)).toBe('hello');
    expect(await store.has(digest('f'))).toBe(false);
    await expect(store.get('sha256:../../etc/passwd' as never)).rejects.toThrow('invalid digest');
  });
});
