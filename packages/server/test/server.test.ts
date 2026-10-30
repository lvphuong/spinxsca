import { createHmac } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { silentLogger } from '@spinxsca/core';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildServer, githubEvent, gitlabEvent, Registry, verifyGithubSignature } from '../src/index';

let dir: string;
let now = new Date('2026-10-30T00:00:00Z');
const clock = { now: () => now };

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'spx-srv-'));
  now = new Date('2026-10-30T00:00:00Z');
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe('job queue', () => {
  it('deduplicates by idempotency key, leases jobs, and retries with backoff', () => {
    const registry = Registry.open(dir);
    try {
      const a = registry.enqueue(
        { kind: 'SCAN', projectId: 'p', payload: { branch: 'main' }, idempotencyKey: 'k1', maxAttempts: 2 },
        now,
      );
      const b = registry.enqueue(
        { kind: 'SCAN', projectId: 'p', payload: { branch: 'main' }, idempotencyKey: 'k1' },
        now,
      );
      expect(a.created).toBe(true);
      expect(b).toEqual({ job: a.job, created: false });
      const claimed = registry.claim(now, 60_000);
      expect(claimed).toMatchObject({ jobId: a.job.jobId, status: 'RUNNING', attempts: 1 });
      expect(registry.claim(now, 60_000)).toBeUndefined();
      // An expired lease (crashed worker) makes the job claimable again.
      const later = new Date(now.getTime() + 61_000);
      expect(registry.claim(later, 60_000)?.attempts).toBe(2);
      // Second attempt fails and max attempts is 2: the job is FAILED for good.
      expect(registry.fail(a.job.jobId, 'boom', later)?.status).toBe('FAILED');

      const c = registry.enqueue({ kind: 'KB_SYNC', payload: {} }, now).job;
      registry.claim(now, 60_000);
      const retried = registry.fail(c.jobId, 'network', now);
      expect(retried).toMatchObject({
        status: 'QUEUED',
        error: 'network',
        runAfter: new Date(now.getTime() + 60_000).toISOString(),
      });
      expect(registry.claim(now, 60_000)).toBeUndefined();
      expect(registry.claim(new Date(now.getTime() + 60_000), 60_000)?.jobId).toBe(c.jobId);
    } finally {
      registry.close();
    }
  });

  it('stores only token hashes and expires sessions', () => {
    const registry = Registry.open(dir);
    try {
      const { token, entry } = registry.createToken('ci', 'member', now);
      expect(token.startsWith('spx_')).toBe(true);
      const raw = JSON.stringify(registry.db.prepare('SELECT * FROM tokens').all());
      expect(raw).not.toContain(token);
      expect(registry.authenticate(token, now)?.tokenId).toBe(entry.tokenId);
      expect(registry.authenticate('spx_wrong', now)).toBeUndefined();
      const session = registry.createSession(entry.tokenId, now, 1);
      expect(registry.sessionToken(session, now)?.name).toBe('ci');
      expect(registry.sessionToken(session, new Date(now.getTime() + 2 * 3_600_000))).toBeUndefined();
      registry.revokeToken(entry.tokenId, now);
      expect(registry.authenticate(token, now)).toBeUndefined();
    } finally {
      registry.close();
    }
  });
});

describe('webhooks', () => {
  it('maps GitHub push and pull_request events', () => {
    expect(githubEvent('p', 'push', { ref: 'refs/heads/main', after: 'abc1234' })).toEqual({
      kind: 'scan',
      payload: { branch: 'main', commit: 'abc1234', mode: 'FULL', trigger: 'webhook' },
      idempotencyKey: 'scan:p:main:abc1234:full',
    });
    expect(githubEvent('p', 'push', { ref: 'refs/heads/x', after: '0000000', deleted: true }).kind).toBe('ignored');
    expect(githubEvent('p', 'push', { ref: 'refs/tags/v1', after: 'abc' }).kind).toBe('ignored');
    expect(githubEvent('p', 'ping', {}).kind).toBe('ignored');
    const pr = githubEvent('p', 'pull_request', {
      action: 'synchronize',
      pull_request: { number: 7, head: { sha: 'h1', ref: 'feature/a' }, base: { sha: 'b1' } },
    });
    expect(pr).toMatchObject({
      kind: 'scan',
      payload: {
        branch: 'feature/a',
        commit: 'h1',
        mode: 'INCREMENTAL',
        diffBase: 'b1',
        fetchRefs: [{ remote: 'refs/pull/7/head', local: 'refs/spinxsca/pr/7' }],
      },
    });
    expect(githubEvent('p', 'pull_request', { action: 'closed', pull_request: {} }).kind).toBe('ignored');
    expect(githubEvent('p', 'push', 'not an object').kind).toBe('ignored');
  });

  it('maps GitLab push and merge request hooks', () => {
    expect(gitlabEvent('p', 'Push Hook', { ref: 'refs/heads/dev', checkout_sha: 'c1' })).toMatchObject({
      kind: 'scan',
      payload: { branch: 'dev', commit: 'c1' },
    });
    expect(gitlabEvent('p', 'Push Hook', { ref: 'refs/heads/dev', checkout_sha: null, after: '0000000000' }).kind).toBe(
      'ignored',
    );
    expect(
      gitlabEvent('p', 'Merge Request Hook', {
        object_attributes: {
          action: 'update',
          iid: 3,
          source_branch: 'f',
          last_commit: { id: 'h' },
          diff_refs: { base_sha: 'b' },
        },
      }),
    ).toMatchObject({
      kind: 'scan',
      payload: { mode: 'INCREMENTAL', diffBase: 'b', fetchRefs: [{ remote: 'refs/merge-requests/3/head' }] },
    });
  });

  it('verifies GitHub signatures in constant time', () => {
    const sig = `sha256=${createHmac('sha256', 's3cret').update('{"a":1}').digest('hex')}`;
    expect(verifyGithubSignature('s3cret', '{"a":1}', sig)).toBe(true);
    expect(verifyGithubSignature('s3cret', '{"a":2}', sig)).toBe(false);
    expect(verifyGithubSignature('s3cret', '{"a":1}', undefined)).toBe(false);
  });
});

describe('HTTP API and web UI', () => {
  const setup = () => {
    const server = buildServer({
      dataDir: dir,
      kbDir: join(dir, 'kb'),
      logger: silentLogger,
      clock,
      engines: () => {
        throw new Error('no scans in this test');
      },
    });
    const admin = server.registry.createToken('admin', 'admin', now).token;
    const viewer = server.registry.createToken('reader', 'viewer', now).token;
    const call = (path: string, init: RequestInit & { token?: string; json?: unknown } = {}) =>
      server.app.request(path, {
        ...init,
        headers: {
          ...(init.token ? { authorization: `Bearer ${init.token}` } : {}),
          ...(init.json !== undefined ? { 'content-type': 'application/json' } : {}),
          ...(init.headers as Record<string, string>),
        },
        ...(init.json !== undefined ? { body: JSON.stringify(init.json) } : {}),
      });
    return { server, admin, viewer, call };
  };

  it('requires tokens and roles, hides webhook secrets, and audits changes', async () => {
    const { server, admin, viewer, call } = setup();
    try {
      expect((await call('/v1/health')).status).toBe(200);
      expect((await call('/v1/projects')).status).toBe(401);
      expect((await call('/v1/projects', { token: 'spx_nope' })).status).toBe(401);
      const project = { name: 'shop', source: { kind: 'git', url: 'https://example.com/<script>shop.git' } };
      expect((await call('/v1/projects', { method: 'POST', token: viewer, json: project })).status).toBe(403);
      const created = await call('/v1/projects', { method: 'POST', token: admin, json: project });
      expect(created.status).toBe(201);
      const body = (await created.json()) as { projectId: string; webhookSecret: string; defaultBranch: string };
      expect(body.webhookSecret.length).toBeGreaterThan(20);
      expect(body.defaultBranch).toBe('main');
      expect((await call('/v1/projects', { method: 'POST', token: admin, json: project })).status).toBe(409);
      expect(
        (
          await call('/v1/projects', {
            method: 'POST',
            token: admin,
            json: { name: 'x', source: { kind: 'local', path: 'relative' } },
          })
        ).status,
      ).toBe(400);
      expect(
        (
          await call('/v1/projects', {
            method: 'POST',
            token: admin,
            json: { name: 'bad name!', source: { kind: 'local', path: dir } },
          })
        ).status,
      ).toBe(400);
      const list = await (await call('/v1/projects', { token: viewer })).json();
      expect(JSON.stringify(list)).not.toContain(body.webhookSecret);

      const overview = (await (await call(`/v1/projects/${body.projectId}`, { token: viewer })).json()) as {
        branches: unknown[];
      };
      expect(overview.branches).toEqual([]);
      const gate = (await (await call(`/v1/projects/${body.projectId}/gate`, { token: viewer })).json()) as {
        passed: boolean;
      };
      expect(gate.passed).toBe(false);

      expect(
        (
          await call(`/v1/projects/${body.projectId}/scans`, {
            method: 'POST',
            token: viewer,
            json: { branch: 'main' },
          })
        ).status,
      ).toBe(403);
      const scan = await call(`/v1/projects/${body.projectId}/scans`, {
        method: 'POST',
        token: admin,
        json: { branch: 'main' },
      });
      expect(scan.status).toBe(202);
      expect(
        (
          await call(`/v1/projects/${body.projectId}/scans`, {
            method: 'POST',
            token: admin,
            json: { branch: 'main', mode: 'incremental' },
          })
        ).status,
      ).toBe(400);

      const token = (await (
        await call('/v1/tokens', { method: 'POST', token: admin, json: { name: 'ci', role: 'member' } })
      ).json()) as { token: string; tokenId: string };
      expect((await call('/v1/projects', { token: token.token })).status).toBe(200);
      expect((await call(`/v1/tokens/${token.tokenId}`, { method: 'DELETE', token: admin })).status).toBe(200);
      expect((await call('/v1/projects', { token: token.token })).status).toBe(401);

      expect((await call('/v1/audit', { token: viewer })).status).toBe(403);
      const audit = (await (await call('/v1/audit', { token: admin })).json()) as Array<{
        action: string;
        actor: string;
      }>;
      expect(audit.map((a) => a.action)).toEqual(['token.revoke', 'token.create', 'scan.enqueue', 'project.create']);
      expect(audit[0]?.actor).toMatch(/^admin \(tok_/);
    } finally {
      await server.close();
    }
  });

  it('accepts signed webhooks once per commit and rejects bad signatures', async () => {
    const { server, admin, call } = setup();
    try {
      const created = (await (
        await call('/v1/projects', {
          method: 'POST',
          token: admin,
          json: { name: 'repo', source: { kind: 'git', url: 'https://example.com/r.git' } },
        })
      ).json()) as { projectId: string; webhookSecret: string };
      const payload = JSON.stringify({ ref: 'refs/heads/main', after: 'abcdef1' });
      const sign = (secret: string) => `sha256=${createHmac('sha256', secret).update(payload).digest('hex')}`;
      const send = (sig: string, event = 'push') =>
        call(`/v1/webhooks/github/${created.projectId}`, {
          method: 'POST',
          body: payload,
          headers: { 'x-hub-signature-256': sig, 'x-github-event': event, 'content-type': 'application/json' },
        });
      expect((await send(sign('wrong'))).status).toBe(401);
      const first = (await (await send(sign(created.webhookSecret))).json()) as { jobId: string; created: boolean };
      const again = (await (await send(sign(created.webhookSecret))).json()) as { jobId: string; created: boolean };
      expect(first.created).toBe(true);
      expect(again).toEqual({ jobId: first.jobId, created: false });
      expect((await (await send(sign(created.webhookSecret), 'ping')).json()) as object).toEqual({ ignored: 'ping' });
      const gitlab = await call(`/v1/webhooks/gitlab/${created.projectId}`, {
        method: 'POST',
        body: JSON.stringify({ ref: 'refs/heads/dev', checkout_sha: 'fedcba9' }),
        headers: { 'x-gitlab-token': created.webhookSecret, 'x-gitlab-event': 'Push Hook' },
      });
      expect(gitlab.status).toBe(202);
      expect(
        server.registry
          .jobs()
          .map((j) => j.payload.branch)
          .sort(),
      ).toEqual(['dev', 'main']);
      expect((await call('/v1/webhooks/github/missing', { method: 'POST', body: '{}' })).status).toBe(404);
    } finally {
      await server.close();
    }
  });

  it('signs in to the web UI with a token and escapes repository data', async () => {
    const { server, admin, call } = setup();
    try {
      await call('/v1/projects', {
        method: 'POST',
        token: admin,
        json: { name: 'shop', source: { kind: 'git', url: 'https://example.com/<script>alert(1)</script>.git' } },
      });
      const anonymous = await call('/ui');
      expect(anonymous.status).toBe(302);
      expect(anonymous.headers.get('location')).toBe('/ui/login');
      const bad = await call('/ui/login', { method: 'POST', body: new URLSearchParams({ token: 'spx_bad' }) });
      expect(bad.status).toBe(401);
      const login = await call('/ui/login', { method: 'POST', body: new URLSearchParams({ token: admin }) });
      expect(login.status).toBe(302);
      const cookie = login.headers.get('set-cookie') ?? '';
      expect(cookie).toMatch(/spx_session=[^;]+; Max-Age=43200; Path=\/; HttpOnly; SameSite=Strict/);
      const home = await call('/ui', { headers: { cookie: cookie.split(';')[0] as string } });
      const html = await home.text();
      expect(home.status).toBe(200);
      expect(html).toContain('shop');
      expect(html).not.toContain('<script>');
      expect(html).toContain('&lt;script&gt;');
      expect(home.headers.get('content-security-policy')).toContain("default-src 'none'");
      // The session authorises JSON reads, never changes (CSRF).
      expect((await call('/v1/projects', { headers: { cookie: cookie.split(';')[0] as string } })).status).toBe(200);
      const forged = await call('/v1/kb/sync', { method: 'POST', headers: { cookie: cookie.split(';')[0] as string } });
      expect(forged.status).toBe(401);
      const logout = await call('/ui/logout', { method: 'POST', headers: { cookie: cookie.split(';')[0] as string } });
      expect(logout.status).toBe(302);
      expect((await call('/ui', { headers: { cookie: cookie.split(';')[0] as string } })).status).toBe(302);
    } finally {
      await server.close();
    }
  });
});
