import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { FsArtifactStore, migrate, SqliteScanRepository } from '../src/index';
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
    expect(migrate(sqlite)).toEqual(['0000_init', '0001_agent_runs']);
    expect(migrate(sqlite)).toEqual([]);
    sqlite.close();
  });
});

repositoryContract('sqlite', async () => {
  const repo = SqliteScanRepository.open(join(dir, 'state.db'));
  return { repo, close: () => repo.close() };
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
