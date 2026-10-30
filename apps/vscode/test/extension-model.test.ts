import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { runCli } from '../src/cli';
import { type CliFinding, diagnosticsFromCli, diagnosticsFromServer, findingsAt, levelOf, summary } from '../src/model';
import { ServerClient } from '../src/server-client';

const cliEntry = (
  id: string,
  state: string,
  severity: CliFinding['assessment']['severity'],
  extra: Partial<CliFinding> = {},
): CliFinding => ({
  finding: { findingId: id, title: 'SQL injection', category: 'SQL_INJECTION', cwe: ['CWE-89'] },
  assessment: { severity, reconciliationState: state, classification: 'POTENTIAL' },
  location: { path: 'routes/users.js', startLine: 10, endLine: 10 },
  disposition: null,
  ...extra,
});

describe('editor model', () => {
  it('turns open CLI findings into diagnostics and skips fixed, suppressed, unlikely and low ones', () => {
    const specs = diagnosticsFromCli(
      [
        cliEntry('SPX-1', 'NEW', 'HIGH'),
        cliEntry('SPX-2', 'RESOLVED', 'HIGH'),
        cliEntry('SPX-3', 'EXISTING', 'HIGH', { disposition: { kind: 'FALSE_POSITIVE' } }),
        cliEntry('SPX-4', 'EXISTING', 'MEDIUM', {
          assessment: { severity: 'MEDIUM', reconciliationState: 'EXISTING', classification: 'UNLIKELY' },
        }),
        cliEntry('SPX-5', 'EXISTING', 'INFO'),
        cliEntry('SPX-6', 'EXISTING', 'CRITICAL', {
          location: { path: 'package-lock.json', startLine: 14, endLine: 18 },
          assessment: {
            severity: 'CRITICAL',
            reconciliationState: 'EXISTING',
            classification: 'POTENTIAL',
            intel: { kev: { dateAdded: '2026-10-30' }, epss: { score: 0.91 } },
          },
        }),
      ],
      'low',
    );
    expect(specs.map((s) => [s.findingId, s.level, s.path])).toEqual([
      ['SPX-6', 'error', 'package-lock.json'],
      ['SPX-1', 'error', 'routes/users.js'],
    ]);
    expect(specs[0]?.message).toBe('SQL injection (SQL_INJECTION, CWE-89) · CISA KEV since 2026-10-30 · EPSS 0.91');
    expect(specs[1]?.message).toContain('· new');
    expect(summary(specs)).toBe('1 critical, 1 high');
    expect(findingsAt(specs, 'package-lock.json', 16).map((s) => s.findingId)).toEqual(['SPX-6']);
    expect(levelOf('LOW')).toBe('information');
    expect(diagnosticsFromCli([cliEntry('SPX-7', 'NEW', 'MEDIUM')], 'high')).toEqual([]);
  });

  it('shows open and not re-evaluated server findings that have a location', () => {
    const specs = diagnosticsFromServer([
      {
        findingId: 'SPX-1',
        title: 't',
        category: 'XSS',
        cwe: [],
        branch: { state: 'OPEN', severity: 'HIGH', location: { path: 'a.js', startLine: 3, endLine: 3 } },
      },
      {
        findingId: 'SPX-2',
        title: 't',
        category: 'XSS',
        cwe: [],
        branch: { state: 'FIXED', severity: 'HIGH', location: { path: 'a.js', startLine: 5, endLine: 5 } },
      },
      {
        findingId: 'SPX-3',
        title: 't',
        category: 'XSS',
        cwe: [],
        branch: {
          state: 'NOT_REEVALUATED',
          severity: 'MEDIUM',
          kev: true,
          location: { path: 'b.js', startLine: 1, endLine: 2 },
        },
      },
      { findingId: 'SPX-4', title: 't', category: 'XSS', cwe: [], branch: { state: 'OPEN', severity: 'HIGH' } },
    ]);
    expect(specs.map((s) => [s.findingId, s.state])).toEqual([
      ['SPX-1', 'OPEN'],
      ['SPX-3', 'NOT_REEVALUATED'],
    ]);
    expect(specs[1]?.message).toContain('CISA KEV · not re-evaluated by the last scan');
  });
});

describe('CLI runner', () => {
  const dir = mkdtempSync(join(tmpdir(), 'spx-vscode-'));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  const fake = (name: string, body: string) => {
    const path = join(dir, name);
    writeFileSync(path, `#!/usr/bin/env node\n${body}\n`);
    chmodSync(path, 0o755);
    return path;
  };

  it('parses JSON on success and on policy failure, reports errors and a missing executable', async () => {
    const ok = fake(
      'ok',
      'process.stdout.write(JSON.stringify({ args: process.argv.slice(2), color: process.env.NO_COLOR }));',
    );
    expect(await runCli(ok, ['findings', 'list', '--json'], dir)).toEqual({
      ok: true,
      exitCode: 0,
      data: { args: ['findings', 'list', '--json'], color: '1' },
    });
    const policy = fake('policy', "process.stdout.write('[1]'); process.exit(1);");
    expect(await runCli(policy, [], dir)).toMatchObject({ ok: true, exitCode: 1, data: [1] });
    const failing = fake(
      'fail',
      "process.stderr.write('› working\\nerror no completed scan found; run `spinxsca scan` first\\n'); process.exit(2);",
    );
    expect(await runCli(failing, [], dir)).toEqual({
      ok: false,
      exitCode: 2,
      error: 'no completed scan found; run `spinxsca scan` first',
    });
    expect((await runCli(join(dir, 'missing'), [], dir)).error).toContain('spinxsca CLI not found');
  });
});

describe('server client', () => {
  it('reads findings and the gate with a bearer token', async () => {
    const seen: string[] = [];
    const http = (async (url: string, init?: RequestInit) => {
      seen.push(`${url} ${new Headers(init?.headers).get('authorization')}`);
      return url.endsWith('/gate?branch=feature%2Fx')
        ? new Response(JSON.stringify({ passed: false, checks: [] }))
        : new Response('[]');
    }) as unknown as typeof fetch;
    const client = new ServerClient('https://spx.example/', 'spx_t', http);
    expect(await client.findings('prj 1', 'feature/x')).toEqual([]);
    expect((await client.gate('prj 1', 'feature/x')).passed).toBe(false);
    expect(seen).toEqual([
      'https://spx.example/v1/projects/prj%201/findings?branch=feature%2Fx Bearer spx_t',
      'https://spx.example/v1/projects/prj%201/gate?branch=feature%2Fx Bearer spx_t',
    ]);
    expect(client.findingUrl('p', 'SPX-1')).toBe('https://spx.example/ui/projects/p/findings/SPX-1');
    const denied = new ServerClient(
      'https://spx.example',
      'bad',
      (async () => new Response('', { status: 401 })) as unknown as typeof fetch,
    );
    await expect(denied.findings('p', 'main')).rejects.toThrow('rejected the API token');
  });
});
