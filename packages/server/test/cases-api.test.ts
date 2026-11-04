import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { silentLogger, verifyChain } from '@spinxsca/core';
import type { ApprovalRecord, ReviewCase } from '@spinxsca/schemas';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildServer, decode, encode } from '../src/index';

let dir: string;
const now = new Date('2026-11-01T00:00:00Z');
const clock = { now: () => now };
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'spx-cases-'));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function setup() {
  const server = buildServer({
    dataDir: dir,
    kbDir: join(dir, 'kb'),
    logger: silentLogger,
    clock,
    worker: false,
    engines: () => {
      throw new Error('no scans in this test');
    },
  });
  const admin = server.registry.createToken('admin', 'admin', now).token;
  const member = server.registry.createToken('alice', 'member', now).token;
  const member2 = server.registry.createToken('bob', 'member', now).token;
  const viewer = server.registry.createToken('reader', 'viewer', now).token;
  const project = server.registry.createProject(
    { name: 'api', source: { kind: 'local', path: dir }, defaultBranch: 'main' },
    now,
  );
  const call = (path: string, init: { method?: string; token?: string; json?: unknown } = {}) =>
    server.app.request(path, {
      method: init.method ?? 'GET',
      headers: {
        ...(init.token ? { authorization: `Bearer ${init.token}` } : {}),
        ...(init.json !== undefined ? { 'content-type': 'application/json' } : {}),
      },
      ...(init.json !== undefined ? { body: JSON.stringify(init.json) } : {}),
    });
  const cases = server.states.get(project.projectId).cases;
  return { server, admin, member, member2, viewer, project, call, cases };
}

const rc = (caseId: string, projectId: string): ReviewCase => ({
  caseId,
  projectId,
  scanId: 'scan_1',
  snapshotId: 'snap_1',
  goal: 'Review the API',
  mode: 'supervised',
  attended: false,
  status: 'PARKED',
  round: 1,
  policyDigest: `sha256:${'e'.repeat(64)}`,
  createdAt: now.toISOString(),
  updatedAt: now.toISOString(),
});
const approval = (overrides: Partial<ApprovalRecord>): ApprovalRecord => ({
  approvalId: 'apr_1',
  projectId: 'prj',
  caseId: 'case_1',
  toolCallId: 'call_1',
  tool: 'validation_run',
  risk: 'EXEC_REPO_CODE',
  humanOnly: false,
  title: 'Run a proof of concept for CF-1',
  summary: 'sandbox',
  effect: 'sandbox',
  targets: [{ kind: 'handle', value: 'CF-1' }],
  argsPreview: '{}',
  offeredGrants: ['once', 'case'],
  status: 'PENDING',
  requestedAt: now.toISOString(),
  ...overrides,
});

describe('case API and inbox', () => {
  it('lists pending approvals, lets the first member decide and resumes the case', async () => {
    const { server, admin, member, member2, viewer, project, call, cases } = setup();
    try {
      await cases.createCase(rc('case_1', project.projectId));
      await cases.createApproval(approval({ projectId: project.projectId }));
      const inbox = (await (await call('/v1/inbox', { token: viewer })).json()) as {
        approvals: Array<{ approvalId: string; project: { name: string } }>;
      };
      expect(inbox.approvals.map((a) => `${a.approvalId}@${a.project.name}`)).toEqual(['apr_1@api']);

      const path = `/v1/projects/${project.projectId}/approvals/apr_1`;
      expect((await call(path, { method: 'POST', token: viewer, json: { decision: 'approve' } })).status).toBe(403);
      const first = await call(path, { method: 'POST', token: member, json: { decision: 'approve', grant: 'case' } });
      expect(first.status).toBe(200);
      const body = (await first.json()) as { approval: ApprovalRecord; grantId?: string; resumeJobId?: string };
      expect(body.approval).toMatchObject({
        status: 'APPROVED',
        grantScope: 'case',
        resolvedBy: { kind: 'human', id: 'alice' },
      });
      expect(body.grantId).toBeDefined();
      expect(server.registry.job(body.resumeJobId as string)).toMatchObject({
        kind: 'CASE_RESUME',
        payload: { caseId: 'case_1' },
      });
      const second = await call(path, { method: 'POST', token: member2, json: { decision: 'deny' } });
      expect(second.status).toBe(409);
      const grants = (await (await call(`/v1/projects/${project.projectId}/grants`, { token: viewer })).json()) as {
        grants: Array<{ scope: string; target: string; createdBy: string }>;
      };
      expect(grants.grants).toEqual([
        expect.objectContaining({ scope: 'case', target: 'handle:CF-1', createdBy: 'human:alice' }),
      ]);
      const grantId = body.grantId as string;
      expect(
        (await call(`/v1/projects/${project.projectId}/grants/${grantId}`, { method: 'DELETE', token: member })).status,
      ).toBe(403);
      expect(
        (await call(`/v1/projects/${project.projectId}/grants/${grantId}`, { method: 'DELETE', token: admin })).status,
      ).toBe(200);
      expect(verifyChain(await cases.listAudit('case_1')).ok).toBe(true);
    } finally {
      await server.close();
    }
  });

  it('never remembers a human-only approval and does not resume a repository change', async () => {
    const { server, member, project, call, cases } = setup();
    try {
      await cases.createCase(rc('case_1', project.projectId));
      await cases.createApproval(
        approval({
          projectId: project.projectId,
          approvalId: 'apr_h',
          toolCallId: 'apply_1',
          tool: 'request_apply',
          risk: 'WRITE_REPO',
          humanOnly: true,
          effect: 'repository',
          offeredGrants: ['once'],
          argsPreview: '{"patchId":"patch_1"}',
        }),
      );
      const res = await call(`/v1/projects/${project.projectId}/approvals/apr_h`, {
        method: 'POST',
        token: member,
        json: { decision: 'approve', grant: 'standing' },
      });
      const body = (await res.json()) as { approval: ApprovalRecord; grantId?: string; resumeJobId?: string };
      expect(body.approval).toMatchObject({ status: 'APPROVED', grantScope: 'once' });
      expect(body.grantId).toBeUndefined();
      expect(body.resumeJobId).toBeUndefined();
      expect(await cases.listGrants({ projectId: project.projectId })).toEqual([]);
    } finally {
      await server.close();
    }
  });

  it('serves case views, project AI settings, review jobs and an event stream', async () => {
    const { server, admin, member, viewer, project, call, cases } = setup();
    try {
      await cases.createCase({ ...rc('case_1', project.projectId), status: 'CONVERGED' });
      await cases.appendAudit({ caseId: 'case_1', stage: 'case.started', actor: 'host', data: {} });
      await cases.appendJournal({
        caseId: 'case_1',
        kind: 'NOTE',
        author: 'host',
        handles: [],
        refs: [],
        text: 'hello',
      });
      const view = (await (await call(`/v1/projects/${project.projectId}/cases/case_1`, { token: viewer })).json()) as {
        case: ReviewCase;
      };
      expect(view.case.status).toBe('CONVERGED');
      expect((await call(`/v1/projects/${project.projectId}/cases/missing`, { token: viewer })).status).toBe(404);

      expect(
        (await call(`/v1/projects/${project.projectId}/ai`, { method: 'PUT', token: member, json: { level: 'deep' } }))
          .status,
      ).toBe(403);
      expect(
        (
          await call(`/v1/projects/${project.projectId}/ai`, {
            method: 'PUT',
            token: admin,
            json: { level: 'deep', goal: 'Find authorization flaws first.' },
          })
        ).status,
      ).toBe(200);
      expect(server.registry.project(project.projectId)?.ai).toEqual({
        level: 'deep',
        goal: 'Find authorization flaws first.',
      });

      const review = await call(`/v1/projects/${project.projectId}/reviews`, {
        method: 'POST',
        token: member,
        json: { branch: 'main' },
      });
      expect(review.status).toBe(201);
      expect(((await review.json()) as { job: { kind: string } }).job.kind).toBe('REVIEW');

      const events = await call(`/v1/projects/${project.projectId}/cases/case_1/events`, { token: viewer });
      const text = await events.text();
      expect(text).toContain('event: audit');
      expect(text).toContain('event: journal');
      expect(text).toContain('event: case');
    } finally {
      await server.close();
    }
  });

  it('keeps human decisions out of the worker case RPC', async () => {
    const { server, project } = setup();
    try {
      const { job } = server.registry.enqueue(
        { kind: 'REVIEW', projectId: project.projectId, payload: { branch: 'main' } },
        now,
      );
      const claimed = server.registry.claim(now, 60_000, { workerId: 'w1' });
      expect(claimed?.jobId).toBe(job.jobId);
      // The RPC route checks the method list before anything else.
      const { workerMayCall } = await import('../src/rpc');
      for (const m of ['resolveApproval', 'saveGrant', 'revokeGrant', 'updateMemoryStatus'])
        expect(workerMayCall(m)).toBe(false);
      expect(decode(encode({ method: 'appendAudit', args: [] }))).toEqual({ method: 'appendAudit', args: [] });
    } finally {
      await server.close();
    }
  });
});

describe('desktop sidecar mode', () => {
  it('accepts the launch token as the local owner only from app origins on loopback', async () => {
    const launchToken = 'x'.repeat(48);
    const server = buildServer({
      dataDir: dir,
      kbDir: join(dir, 'kb'),
      logger: silentLogger,
      clock,
      worker: false,
      desktop: { launchToken },
      engines: () => {
        throw new Error('unused');
      },
    });
    try {
      const get = (headers: Record<string, string>) => server.app.request('/v1/projects', { headers });
      const ok = await get({
        host: '127.0.0.1:41234',
        authorization: `Bearer ${launchToken}`,
        origin: 'tauri://localhost',
      });
      expect(ok.status).toBe(200);
      expect(ok.headers.get('access-control-allow-origin')).toBe('tauri://localhost');
      expect((await get({ host: 'evil.example:41234', authorization: `Bearer ${launchToken}` })).status).toBe(403);
      expect(
        (await get({ host: '127.0.0.1:41234', authorization: `Bearer ${launchToken}`, origin: 'https://evil.example' }))
          .status,
      ).toBe(403);
      expect((await get({ host: '127.0.0.1:41234', authorization: `Bearer ${'y'.repeat(48)}` })).status).toBe(401);
    } finally {
      await server.close();
    }
  });

  it('refuses to listen beyond loopback', async () => {
    const { startServer } = await import('../src/index');
    await expect(
      startServer({
        dataDir: dir,
        kbDir: join(dir, 'kb'),
        logger: silentLogger,
        host: '0.0.0.0',
        port: 0,
        desktop: { launchToken: 'x'.repeat(48) },
        engines: () => {
          throw new Error('unused');
        },
      }),
    ).rejects.toThrow('loopback');
  });
});
