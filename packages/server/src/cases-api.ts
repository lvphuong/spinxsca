import {
  answerContextQuestion,
  type CaseRepository,
  declineContextQuestion,
  isContextQuestion,
  latestVerdicts,
  newId,
} from '@spinxsca/core';
import { type ApprovalRequest, grantFromApproval, validateGrant } from '@spinxsca/governance';
import type { ApprovalRecord, GrantScope } from '@spinxsca/schemas';
import type { Hono, MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { streamSSE } from 'hono/streaming';
import { z } from 'zod';
import type { Env } from './app';
import type { ProjectEntry, Registry, Role, TokenEntry } from './registry';
import type { ProjectStates } from './state';

const ApprovalDecision = z.strictObject({
  decision: z.enum(['approve', 'deny', 'answer']),
  grant: z.enum(['once', 'case', 'standing']).default('once'),
  reason: z.string().min(1).max(2000).optional(),
  /** `answer`: a review question from recon (ADR-051); the answer becomes claimed project memory. */
  answer: z.string().min(1).max(2000).optional(),
  provenance: z.string().min(1).max(200).optional(),
});
const ProjectAi = z.strictObject({
  level: z.enum(['off', 'explain', 'standard', 'deep']),
  goal: z.string().min(10).max(4000).optional(),
  objectives: z.array(z.string().min(5).max(400)).max(10).optional(),
});
const ReviewInput = z.strictObject({
  branch: z.string().min(1).max(255),
  commit: z
    .string()
    .regex(/^[0-9a-f]{7,64}$/)
    .optional(),
  goal: z.string().min(10).max(4000).optional(),
  objectives: z.array(z.string().min(5).max(400)).max(10).optional(),
});

export interface CaseApiContext {
  registry: Registry;
  states: ProjectStates;
  clock: { now(): Date };
  authenticate: MiddlewareHandler<Env>;
  role: (min: Role) => MiddlewareHandler<Env>;
  audit: (
    c: { get: (k: 'actor') => TokenEntry },
    action: string,
    target?: string,
    detail?: Record<string, unknown>,
  ) => void;
  projectOr404: (id: string) => ProjectEntry;
  /** SSE poll interval (tests use a short one). */
  pollMs?: number;
}

function toRequest(a: ApprovalRecord): ApprovalRequest {
  return {
    approvalId: a.approvalId,
    projectId: a.projectId,
    caseId: a.caseId,
    toolCallId: a.toolCallId,
    tool: a.tool,
    risk: a.risk,
    humanOnly: a.humanOnly,
    title: a.title,
    summary: a.summary,
    effect: a.effect,
    targets: a.targets,
    argsPreview: a.argsPreview,
    ...(a.diff ? { diff: a.diff } : {}),
    offeredGrants: a.offeredGrants,
    flags: [],
  };
}

/**
 * Review cases over the API (ADR-047): case views, the durable inbox, approval resolution (first
 * responder wins; human-only requests need a human token and are approved once), grants, per-project
 * AI settings, review jobs and a server-sent event stream of the case's audit and journal.
 */
export function mountCaseApi(app: Hono<Env>, ctx: CaseApiContext): void {
  const { registry, states, clock, authenticate, role, audit, projectOr404 } = ctx;
  const casesOf = (projectId: string): CaseRepository => states.get(projectId).cases;
  const caseOr404 = async (projectId: string, caseId: string) => {
    const rc = await casesOf(projectId).getCase(caseId);
    if (!rc) throw new HTTPException(404, { message: 'case not found' });
    return rc;
  };

  app.get('/v1/projects/:id/cases', authenticate, async (c) => {
    const project = projectOr404(c.req.param('id'));
    if (!states.exists(project.projectId)) return c.json({ cases: [] });
    return c.json({ cases: await casesOf(project.projectId).listCases({ limit: 100 }) });
  });

  app.get('/v1/projects/:id/cases/:caseId', authenticate, async (c) => {
    const project = projectOr404(c.req.param('id'));
    const cases = casesOf(project.projectId);
    const rc = await caseOr404(project.projectId, c.req.param('caseId'));
    return c.json({
      case: rc,
      objectives: await cases.listObjectives(rc.caseId),
      items: await cases.listWorkItems(rc.caseId),
      handles: (await cases.listHandles(rc.caseId)).map(({ draft: _draft, ...h }) => h),
      verdicts: [...latestVerdicts(await cases.listVerdicts(rc.caseId)).values()],
      checks: await cases.listChecks(rc.caseId),
      ledger: await cases.getLedger(rc.caseId),
      approvals: await cases.listApprovals({ caseId: rc.caseId }),
    });
  });

  app.get('/v1/projects/:id/cases/:caseId/events', authenticate, async (c) => {
    const project = projectOr404(c.req.param('id'));
    const cases = casesOf(project.projectId);
    const rc = await caseOr404(project.projectId, c.req.param('caseId'));
    let auditSeq = Number(c.req.query('sinceSeq') ?? -1);
    let journalSeq = Number(c.req.query('sinceJournal') ?? -1);
    const pollMs = ctx.pollMs ?? 1000;
    return streamSSE(c, async (stream) => {
      let idle = 0;
      while (!stream.aborted && idle < 600_000 / pollMs) {
        const audit = await cases.listAudit(rc.caseId, auditSeq);
        const journal = await cases.listJournal(rc.caseId, journalSeq);
        for (const e of audit) {
          await stream.writeSSE({ event: 'audit', id: `a${e.seq}`, data: JSON.stringify(e) });
          auditSeq = e.seq;
        }
        for (const e of journal) {
          await stream.writeSSE({ event: 'journal', id: `j${e.seq}`, data: JSON.stringify(e) });
          journalSeq = e.seq;
        }
        const current = await cases.getCase(rc.caseId);
        const terminal = current && !['RUNNING', 'PARKED'].includes(current.status);
        if (audit.length || journal.length) idle = 0;
        else idle++;
        if (terminal && !audit.length && !journal.length) {
          await stream.writeSSE({ event: 'case', data: JSON.stringify(current) });
          break;
        }
        await stream.sleep(pollMs);
      }
    });
  });

  app.get('/v1/inbox', authenticate, async (c) => {
    const items = [];
    for (const project of registry.projects()) {
      if (!states.exists(project.projectId)) continue;
      for (const a of await casesOf(project.projectId).listApprovals({ status: 'PENDING' })) {
        items.push({ ...a, project: { projectId: project.projectId, name: project.name } });
      }
    }
    items.sort((a, b) => a.requestedAt.localeCompare(b.requestedAt));
    return c.json({ approvals: items });
  });

  app.post('/v1/projects/:id/approvals/:approvalId', authenticate, role('member'), async (c) => {
    const project = projectOr404(c.req.param('id'));
    const body = ApprovalDecision.parse(await c.req.json());
    const cases = casesOf(project.projectId);
    const approval = await cases.getApproval(c.req.param('approvalId'));
    if (!approval) throw new HTTPException(404, { message: 'approval not found' });
    const actor = c.get('actor');
    if (isContextQuestion(approval)) {
      // Review questions are answered or declined; the answer is a claimed fact, never a grant.
      if (body.decision === 'approve')
        throw new HTTPException(400, {
          message: 'a review question is answered, not approved: send decision "answer"',
        });
      if (body.decision === 'answer' && (!body.answer || !body.provenance))
        throw new HTTPException(400, { message: 'answer and provenance are required' });
      try {
        const resolved =
          body.decision === 'answer'
            ? await answerContextQuestion(cases, approval.approvalId, {
                answer: body.answer as string,
                provenance: body.provenance as string,
                by: actor.name,
                now: clock.now(),
              })
            : {
                approval: await declineContextQuestion(cases, approval.approvalId, {
                  by: actor.name,
                  ...(body.reason ? { reason: body.reason } : {}),
                  now: clock.now(),
                }),
                retriaged: [] as string[],
              };
        audit(c, 'approval.resolve', approval.approvalId, { status: resolved.approval.status, tool: approval.tool });
        const resume = resolved.retriaged.length
          ? registry.enqueue(
              {
                kind: 'CASE_RESUME',
                projectId: project.projectId,
                payload: { caseId: approval.caseId, trigger: 'api' },
                idempotencyKey: `resume:${approval.caseId}:${approval.approvalId}`,
                pool: project.workerPool,
              },
              clock.now(),
            )
          : undefined;
        return c.json({
          approval: resolved.approval,
          retriaged: resolved.retriaged,
          ...(resume ? { resumeJobId: resume.job.jobId } : {}),
        });
      } catch (err) {
        if (/already (approved|denied|expired|cancelled)/.test((err as Error).message))
          return c.json({ error: 'already resolved', approval: await cases.getApproval(approval.approvalId) }, 409);
        throw err;
      }
    }
    if (body.decision === 'answer') throw new HTTPException(400, { message: 'only review questions take an answer' });
    // Grants are validated by the host: human-only requests and scopes not offered become "once".
    const checked = validateGrant(toRequest(approval), {
      status: body.decision === 'approve' ? 'approved' : 'denied',
      by: { kind: 'human', id: actor.name },
      grant: body.grant as GrantScope,
      ...(body.reason ? { reason: body.reason } : {}),
    });
    const now = clock.now().toISOString();
    const { won, approval: stored } = await cases.resolveApproval(approval.approvalId, {
      status: checked.status === 'approved' ? 'APPROVED' : 'DENIED',
      resolvedBy: { kind: 'human', id: actor.name },
      ...(checked.status === 'approved' && checked.grant ? { grantScope: checked.grant } : {}),
      ...(body.reason ? { reason: body.reason } : {}),
      resolvedAt: now,
    });
    if (!won) return c.json({ error: 'already resolved', approval: stored }, 409);
    await cases.appendAudit({
      caseId: approval.caseId,
      stage: 'approval.resolved',
      actor: `human:${actor.name}`,
      toolCallId: approval.toolCallId,
      data: {
        approvalId: approval.approvalId,
        status: stored.status,
        grant: stored.grantScope ?? null,
        notes: checked.notes ?? [],
      },
    });
    let grantId: string | undefined;
    if (stored.status === 'APPROVED') {
      const grant = grantFromApproval(toRequest(approval), checked, { grantId: newId('grant'), now: clock.now() });
      if (grant) {
        await cases.saveGrant(grant);
        grantId = grant.grantId;
        await cases.appendAudit({
          caseId: approval.caseId,
          stage: 'grant.created',
          actor: `human:${actor.name}`,
          data: { grantId, scope: grant.scope, tool: grant.tool, target: grant.target },
        });
      }
    }
    audit(c, 'approval.resolve', approval.approvalId, {
      status: stored.status,
      tool: approval.tool,
      grant: stored.grantScope,
    });
    // The parked case continues where it stopped; patch application stays a local, explicit step.
    const resume =
      approval.tool === 'request_apply'
        ? undefined
        : registry.enqueue(
            {
              kind: 'CASE_RESUME',
              projectId: project.projectId,
              payload: { caseId: approval.caseId, trigger: 'api' },
              idempotencyKey: `resume:${approval.caseId}:${approval.approvalId}`,
              pool: project.workerPool,
            },
            clock.now(),
          );
    return c.json({
      approval: stored,
      ...(grantId ? { grantId } : {}),
      ...(resume ? { resumeJobId: resume.job.jobId } : {}),
    });
  });

  app.get('/v1/projects/:id/grants', authenticate, async (c) => {
    const project = projectOr404(c.req.param('id'));
    return c.json({
      grants: states.exists(project.projectId)
        ? await casesOf(project.projectId).listGrants({ projectId: project.projectId })
        : [],
    });
  });

  app.delete('/v1/projects/:id/grants/:grantId', authenticate, role('admin'), async (c) => {
    const project = projectOr404(c.req.param('id'));
    const ok = await casesOf(project.projectId).revokeGrant(c.req.param('grantId'), clock.now().toISOString());
    if (!ok) throw new HTTPException(404, { message: 'grant not found or already revoked' });
    audit(c, 'grant.revoke', c.req.param('grantId'));
    return c.json({ revoked: true });
  });

  app.put('/v1/projects/:id/ai', authenticate, role('admin'), async (c) => {
    const project = projectOr404(c.req.param('id'));
    const body = ProjectAi.parse(await c.req.json());
    registry.setProjectAi(project.projectId, body.level === 'off' && !body.goal ? null : body);
    audit(c, 'project.ai', project.projectId, { level: body.level });
    return c.json({ ai: body });
  });

  app.post('/v1/projects/:id/reviews', authenticate, role('member'), async (c) => {
    const project = projectOr404(c.req.param('id'));
    const body = ReviewInput.parse(await c.req.json());
    const { job, created } = registry.enqueue(
      {
        kind: 'REVIEW',
        projectId: project.projectId,
        payload: { ...body, trigger: 'api' },
        pool: project.workerPool,
        ...(body.commit ? { idempotencyKey: `review:${project.projectId}:${body.commit}` } : {}),
      },
      clock.now(),
    );
    audit(c, 'review.enqueue', job.jobId, { branch: body.branch });
    return c.json({ job }, created ? 201 : 200);
  });
}
