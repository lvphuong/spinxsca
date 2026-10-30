import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PgScanRepository } from '../src/index';
import { repositoryContract } from './contract';

const IMAGE = 'postgres:17-alpine';
const dockerReady = (() => {
  try {
    execFileSync('docker', ['image', 'inspect', IMAGE], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
})();

let container = '';
let pool: pg.Pool;

async function startPostgres(): Promise<pg.Pool> {
  container = execFileSync('docker', [
    'run',
    '-d',
    '--rm',
    '-e',
    'POSTGRES_PASSWORD=spx',
    '-p',
    '127.0.0.1::5432',
    IMAGE,
  ])
    .toString()
    .trim();
  const port = execFileSync('docker', ['port', container, '5432/tcp']).toString().trim().split(':').pop();
  const p = new pg.Pool({ connectionString: `postgres://postgres:spx@127.0.0.1:${port}/postgres`, max: 8 });
  for (let i = 0; i < 60; i++) {
    try {
      await p.query('SELECT 1');
      return p;
    } catch {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  throw new Error('postgres did not start');
}

describe.runIf(dockerReady)('PgScanRepository (docker)', () => {
  beforeAll(async () => {
    pool = await startPostgres();
  }, 60_000);
  afterAll(async () => {
    await pool?.end();
    if (container) execFileSync('docker', ['rm', '-f', container], { stdio: 'pipe' });
  });

  repositoryContract('postgres', async () => {
    const repo = PgScanRepository.open({ pool, schema: `t_${randomBytes(6).toString('hex')}` });
    return { repo, close: () => repo.close() };
  });

  it('isolates projects by schema and serialises concurrent first opens', async () => {
    const schema = `t_${randomBytes(6).toString('hex')}`;
    const [a, b] = [PgScanRepository.open({ pool, schema }), PgScanRepository.open({ pool, schema })];
    const [pa, pb] = await Promise.all([
      a.ensureProject({ name: 'one', rootPath: '/1' }),
      b.ensureProject({ name: 'two', rootPath: '/2' }),
    ]);
    expect(pb.project.projectId).toBe(pa.project.projectId);
    const other = PgScanRepository.open({ pool, schema: `t_${randomBytes(6).toString('hex')}` });
    const po = await other.ensureProject({ name: 'other', rootPath: '/o' });
    expect(po.project.projectId).not.toBe(pa.project.projectId);
    expect(await other.listFindings(pa.project.projectId)).toEqual([]);
    expect(PgScanRepository.schemaFor('srvprj_01ABC-x')).toBe('spx_srvprj_01abc_x');
    expect(() => PgScanRepository.open({ pool, schema: 'bad"; DROP SCHEMA public; --' })).toThrow(
      'invalid schema name',
    );
    for (const r of [a, b, other]) await r.close();
  });
});
