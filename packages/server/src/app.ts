import { existsSync, statSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { type Clock, disposeFinding, type ReleaseGatePolicy, SpinxscaError } from '@spinxsca/core';
import { LocalKnowledgeBase } from '@spinxsca/kb';
import type { FindingOccurrence } from '@spinxsca/schemas';
import { type Context, Hono, type MiddlewareHandler } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { getCookie } from 'hono/cookie';
import { HTTPException } from 'hono/http-exception';
import { secureHeaders } from 'hono/secure-headers';
import { z } from 'zod';
import { type Registry, ROLE_RANK, type Role, safeEqual, type TokenEntry } from './registry';
import type { ProjectStates } from './state';
import { mountUi, SESSION_COOKIE } from './ui';
import { findingDetail, gateFor, projectOverview, publicProject } from './views';
import { githubEvent, gitlabEvent, verifyGithubSignature, type WebhookOutcome } from './webhooks';
import type { ScanPayload } from './worker';
import { mountWorkerApi, type WorkerApiContext } from './worker-api';

export interface AppContext {
  registry: Registry;
  states: ProjectStates;
  clock: Clock;
  gatePolicy: ReleaseGatePolicy;
  kbDir: string;
  /** Set the session cookie with the Secure flag (behind HTTPS). */
  secureCookies?: boolean;
  /** Remote worker protocol; omitted when only the in-process worker runs jobs. */
  workerApi?: WorkerApiContext;
}

export type Env = { Variables: { actor: TokenEntry } };

const ProjectInput = z.strictObject({
  name: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/, 'letters, digits, . _ - (max 100)'),
  source: z.discriminatedUnion('kind', [
    z.strictObject({ kind: z.literal('git'), url: z.string().min(1).max(2000) }),
    z.strictObject({ kind: z.literal('local'), path: z.string().min(1) }),
  ]),
  defaultBranch: z.string().min(1).max(255).default('main'),
  workerPool: z
    .string()
    .regex(/^[a-z0-9][a-z0-9-]{0,40}$/)
    .default('default'),
});
const ScanInput = z.strictObject({
  branch: z.string().min(1).max(255),
  mode: z.enum(['full', 'incremental']).default('full'),
  diffBase: z.string().min(1).max(255).optional(),
  commit: z
    .string()
    .regex(/^[0-9a-f]{7,64}$/)
    .optional(),
});
const DispositionInput = z.strictObject({
  kind: z.enum(['FALSE_POSITIVE', 'ACCEPTED_RISK', 'WONT_FIX', 'DUPLICATE_OF']),
  reason: z.string().min(3).max(2000),
  expiresAt: z.iso.datetime().optional(),
  duplicateOf: z.string().optional(),
});
const WorkerProvisionInput = z.strictObject({
  pools: z
    .array(z.string().regex(/^[a-z0-9][a-z0-9-]{0,40}$/))
    .min(1)
    .default(['default']),
  ttlMinutes: z.number().int().min(5).max(1440).default(60),
  maxUses: z.number().int().min(1).max(100).default(1),
});
const TokenInput = z.strictObject({ name: z.string().min(1).max(100), role: z.enum(['admin', 'member', 'viewer']) });

/** Longest accepted-risk window the server accepts (accepted risk always expires). */
const MAX_ACCEPTED_RISK_DAYS = 180;

export function createApp(ctx: AppContext): Hono<Env> {
  const { registry, states, clock } = ctx;
  const app = new Hono<Env>();
  app.use(
    '*',
    secureHeaders({
      contentSecurityPolicy: {
        defaultSrc: ["'none'"],
        styleSrc: ["'unsafe-inline'"],
        imgSrc: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
      },
      referrerPolicy: 'no-referrer',
    }),
  );
  // Worker uploads (artifacts, reconciliation commits) are larger than user requests.
  const tooLarge = (c: Context) => c.json({ error: 'request body too large' }, 413);
  const limits = {
    artifacts: bodyLimit({ maxSize: 512 * 1024 * 1024, onError: tooLarge }),
    worker: bodyLimit({ maxSize: 64 * 1024 * 1024, onError: tooLarge }),
    user: bodyLimit({ maxSize: 5 * 1024 * 1024, onError: tooLarge }),
  };
  app.use('*', (c, next) => {
    const path = c.req.path;
    const limit = /^\/v1\/worker\/jobs\/[^/]+\/artifacts$/.test(path)
      ? limits.artifacts
      : path.startsWith('/v1/worker')
        ? limits.worker
        : limits.user;
    return limit(c, next);
  });
  app.onError((err, c) => {
    if (err instanceof HTTPException) return c.json({ error: err.message }, err.status);
    if (err instanceof z.ZodError)
      return c.json(
        { error: 'invalid request', issues: err.issues.map((i) => `${i.path.join('.')}: ${i.message}`) },
        400,
      );
    if (err instanceof SpinxscaError) return c.json({ error: err.message }, err.code === 'NOT_FOUND' ? 404 : 400);
    return c.json({ error: 'internal error' }, 500);
  });

  const authenticate: MiddlewareHandler<Env> = async (c, next) => {
    const header = c.req.header('authorization');
    const bearer = header?.startsWith('Bearer ') ? header.slice(7).trim() : undefined;
    // The web session cookie authorises reads only; every change needs a bearer token, so a forged
    // cross-site request cannot act with a signed-in user's cookie.
    const readOnly = c.req.method === 'GET' || c.req.method === 'HEAD';
    const session = readOnly ? getCookie(c, SESSION_COOKIE) : undefined;
    const actor = bearer
      ? registry.authenticate(bearer, clock.now())
      : session
        ? registry.sessionToken(session, clock.now())
        : undefined;
    if (!actor) throw new HTTPException(401, { message: 'authentication required' });
    c.set('actor', actor);
    await next();
  };
  const role =
    (min: Role): MiddlewareHandler<Env> =>
    async (c, next) => {
      if (ROLE_RANK[c.get('actor').role] < ROLE_RANK[min])
        throw new HTTPException(403, { message: `requires ${min} role` });
      await next();
    };
  const audit = (
    c: { get: (k: 'actor') => TokenEntry },
    action: string,
    target?: string,
    detail?: Record<string, unknown>,
  ) => registry.audit(`${c.get('actor').name} (${c.get('actor').tokenId})`, action, target, detail, clock.now());
  const projectOr404 = (id: string) => {
    const p = registry.project(id);
    if (!p) throw new HTTPException(404, { message: 'project not found' });
    return p;
  };
  const kbCreatedAt = async (id: string) => {
    const kb = LocalKnowledgeBase.open(ctx.kbDir);
    try {
      return kb.store.snapshot(id)?.createdAt;
    } finally {
      kb.close();
    }
  };

  app.get('/v1/health', (c) => c.json({ status: 'ok' }));

  // Webhooks authenticate with the per-project secret, not with API tokens.
  app.post('/v1/webhooks/:provider/:projectId', async (c) => {
    const project = registry.project(c.req.param('projectId'));
    const raw = await c.req.text();
    if (!project) throw new HTTPException(404, { message: 'project not found' });
    let outcome: WebhookOutcome;
    if (c.req.param('provider') === 'github') {
      if (!verifyGithubSignature(project.webhookSecret, raw, c.req.header('x-hub-signature-256')))
        throw new HTTPException(401, { message: 'invalid signature' });
      outcome = githubEvent(project.projectId, c.req.header('x-github-event'), JSON.parse(raw));
    } else if (c.req.param('provider') === 'gitlab') {
      if (!safeEqual(project.webhookSecret, c.req.header('x-gitlab-token') ?? ''))
        throw new HTTPException(401, { message: 'invalid token' });
      outcome = gitlabEvent(project.projectId, c.req.header('x-gitlab-event'), JSON.parse(raw));
    } else throw new HTTPException(404, { message: 'unknown provider' });
    if (outcome.kind === 'ignored') return c.json({ ignored: outcome.reason }, 202);
    if (project.source.kind !== 'git') return c.json({ ignored: 'local projects are not scanned from webhooks' }, 202);
    const { job, created } = registry.enqueue(
      {
        kind: 'SCAN',
        projectId: project.projectId,
        payload: { ...outcome.payload },
        idempotencyKey: outcome.idempotencyKey,
      },
      clock.now(),
    );
    registry.audit(
      `webhook:${c.req.param('provider')}`,
      'scan.enqueue',
      project.projectId,
      { jobId: job.jobId, branch: outcome.payload.branch, created },
      clock.now(),
    );
    return c.json({ jobId: job.jobId, created }, 202);
  });

  if (ctx.workerApi) mountWorkerApi(app as unknown as Hono, ctx.workerApi);

  const v1 = new Hono<Env>();
  v1.use('*', authenticate);

  v1.get('/projects', (c) => c.json(registry.projects().map(publicProject)));
  v1.post('/projects', role('admin'), async (c) => {
    const input = ProjectInput.parse(await c.req.json());
    if (
      input.source.kind === 'local' &&
      (!isAbsolute(input.source.path) || !existsSync(input.source.path) || !statSync(input.source.path).isDirectory())
    ) {
      throw new HTTPException(400, { message: 'local source path must be an existing absolute directory' });
    }
    if (input.source.kind === 'git' && /^(ext|fd)::/i.test(input.source.url))
      throw new HTTPException(400, { message: 'unsupported git transport' });
    if (registry.projects().some((p) => p.name === input.name))
      throw new HTTPException(409, { message: 'a project with this name exists' });
    const project = registry.createProject(input, clock.now());
    audit(c, 'project.create', project.projectId, { name: project.name, source: project.source });
    return c.json({ ...publicProject(project), webhookSecret: project.webhookSecret }, 201);
  });
  v1.get('/projects/:id', async (c) => {
    const project = projectOr404(c.req.param('id'));
    return c.json(await projectOverview(states.get(project.projectId), project, clock));
  });
  v1.get('/projects/:id/webhook', role('admin'), (c) => {
    const project = projectOr404(c.req.param('id'));
    return c.json({
      github: `/v1/webhooks/github/${project.projectId}`,
      gitlab: `/v1/webhooks/gitlab/${project.projectId}`,
      secret: project.webhookSecret,
    });
  });
  v1.post('/projects/:id/scans', role('member'), async (c) => {
    const project = projectOr404(c.req.param('id'));
    const input = ScanInput.parse(await c.req.json());
    if (input.mode === 'incremental' && !input.diffBase)
      throw new HTTPException(400, { message: 'incremental scans need diffBase' });
    if (project.source.kind === 'local' && (input.commit || input.mode === 'incremental')) {
      throw new HTTPException(400, {
        message: 'local projects are scanned as they are on disk (full mode, no commit)',
      });
    }
    const payload: ScanPayload = {
      branch: input.branch,
      mode: input.mode === 'incremental' ? 'INCREMENTAL' : 'FULL',
      ...(input.commit ? { commit: input.commit } : {}),
      ...(input.diffBase ? { diffBase: input.diffBase } : {}),
      trigger: 'api',
    };
    const { job } = registry.enqueue(
      { kind: 'SCAN', projectId: project.projectId, payload: { ...payload } },
      clock.now(),
    );
    audit(c, 'scan.enqueue', project.projectId, { jobId: job.jobId, branch: input.branch, mode: input.mode });
    return c.json(job, 202);
  });
  v1.get('/projects/:id/scans', async (c) => {
    const project = projectOr404(c.req.param('id'));
    const state = states.get(project.projectId);
    const engineProject = await state.engineProjectId();
    const scans = engineProject ? await state.repo.listScans(engineProject, 100) : [];
    return c.json(
      scans.map((s) => ({
        scanId: s.scanId,
        mode: s.mode,
        status: s.status,
        branch: s.manifest.source.branch,
        commit: s.manifest.source.commitSha,
        requestedAt: s.requestedAt,
        completedAt: s.completedAt,
        summary: s.summary,
      })),
    );
  });
  v1.get('/projects/:id/findings', async (c) => {
    const project = projectOr404(c.req.param('id'));
    const state = states.get(project.projectId);
    const overview = await projectOverview(state, project, clock);
    const branch = c.req.query('branch');
    if (!branch) return c.json(overview.findings);
    // With a branch, each row carries the primary location from the scan that decided its state
    // (editor integrations place diagnostics with it).
    const occurrences = new Map<string, Map<string, FindingOccurrence>>();
    const rows = [];
    for (const f of overview.findings) {
      const cell = f.branches[branch];
      if (!cell) continue;
      if (!occurrences.has(cell.scanId))
        occurrences.set(
          cell.scanId,
          new Map((await state.repo.listOccurrences(cell.scanId)).map((o) => [o.findingId, o])),
        );
      const location = occurrences.get(cell.scanId)?.get(f.findingId)?.locations[0];
      rows.push({ ...f, branch: { ...cell, ...(location ? { location } : {}) } });
    }
    return c.json(rows);
  });
  v1.get('/projects/:id/findings/:findingId', async (c) => {
    const project = projectOr404(c.req.param('id'));
    const detail = await findingDetail(states.get(project.projectId), c.req.param('findingId'), clock);
    if (!detail) throw new HTTPException(404, { message: 'finding not found' });
    return c.json(detail);
  });
  v1.post('/projects/:id/findings/:findingId/dispositions', role('member'), async (c) => {
    const project = projectOr404(c.req.param('id'));
    const input = DispositionInput.parse(await c.req.json());
    if (input.kind === 'ACCEPTED_RISK') {
      if (!input.expiresAt) throw new HTTPException(400, { message: 'accepted risk needs expiresAt' });
      if (Date.parse(input.expiresAt) - clock.now().getTime() > MAX_ACCEPTED_RISK_DAYS * 86_400_000) {
        throw new HTTPException(400, { message: `accepted risk may last at most ${MAX_ACCEPTED_RISK_DAYS} days` });
      }
    }
    const actor = c.get('actor');
    const disposition = await disposeFinding(states.get(project.projectId).repo, clock, {
      findingId: c.req.param('findingId'),
      kind: input.kind,
      reason: input.reason,
      decidedBy: `${actor.name} (${actor.tokenId})`,
      ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
      ...(input.duplicateOf ? { duplicateOf: input.duplicateOf } : {}),
    });
    audit(c, 'finding.dispose', `${project.projectId}/${disposition.findingId}`, {
      kind: disposition.kind,
      reason: disposition.reason,
      expiresAt: disposition.expiresAt,
    });
    return c.json(disposition, 201);
  });
  v1.get('/projects/:id/gate', async (c) => {
    const project = projectOr404(c.req.param('id'));
    const branch = c.req.query('branch') ?? project.defaultBranch;
    return c.json(await gateFor(states.get(project.projectId), branch, ctx.gatePolicy, clock, kbCreatedAt));
  });
  v1.get('/projects/:id/jobs', (c) =>
    c.json(registry.jobs({ projectId: projectOr404(c.req.param('id')).projectId, limit: 50 })),
  );

  v1.get('/jobs', (c) => c.json(registry.jobs({ limit: 100 })));
  v1.get('/jobs/:jobId', (c) => {
    const job = registry.job(c.req.param('jobId'));
    if (!job) throw new HTTPException(404, { message: 'job not found' });
    return c.json(job);
  });

  v1.get('/kb', (c) => {
    const kb = LocalKnowledgeBase.open(ctx.kbDir);
    try {
      return c.json({
        latest: kb.store.latestSnapshot() ?? null,
        stats: kb.store.stats(),
        sources: kb.store.sources(),
      });
    } finally {
      kb.close();
    }
  });
  v1.post('/kb/sync', role('admin'), (c) => {
    const { job } = registry.enqueue({ kind: 'KB_SYNC', payload: { trigger: 'api' } }, clock.now());
    audit(c, 'kb.sync', undefined, { jobId: job.jobId });
    return c.json(job, 202);
  });

  v1.get('/tokens', role('admin'), (c) => c.json(registry.tokens()));
  v1.post('/tokens', role('admin'), async (c) => {
    const input = TokenInput.parse(await c.req.json());
    const { token, entry } = registry.createToken(input.name, input.role, clock.now());
    audit(c, 'token.create', entry.tokenId, { name: entry.name, role: entry.role });
    return c.json({ ...entry, token }, 201);
  });
  v1.delete('/tokens/:tokenId', role('admin'), (c) => {
    if (!registry.revokeToken(c.req.param('tokenId'), clock.now()))
      throw new HTTPException(404, { message: 'token not found' });
    audit(c, 'token.revoke', c.req.param('tokenId'));
    return c.json({ revoked: true });
  });
  v1.post('/workers/provision', role('admin'), async (c) => {
    const input = WorkerProvisionInput.parse(await c.req.json().catch(() => ({})));
    const actor = c.get('actor');
    const issued = registry.createProvisioningToken(
      input.pools,
      `${actor.name} (${actor.tokenId})`,
      clock.now(),
      input.ttlMinutes,
      input.maxUses,
    );
    audit(c, 'worker.provision', undefined, {
      pools: input.pools,
      expiresAt: issued.expiresAt,
      maxUses: input.maxUses,
    });
    return c.json({ provisioningToken: issued.token, expiresAt: issued.expiresAt, pools: input.pools }, 201);
  });
  v1.get('/workers', role('admin'), (c) => c.json(registry.workers()));
  v1.delete('/workers/:workerId', role('admin'), (c) => {
    if (!registry.revokeWorker(c.req.param('workerId'), clock.now()))
      throw new HTTPException(404, { message: 'worker not found' });
    audit(c, 'worker.revoke', c.req.param('workerId'));
    return c.json({ revoked: true });
  });
  v1.get('/kb/public-key', (c) =>
    c.json({
      publicKey: ctx.workerApi?.signingKey.publicKeyPem ?? null,
      keyId: ctx.workerApi?.signingKey.keyId ?? null,
    }),
  );
  v1.get('/audit', role('admin'), (c) => c.json(registry.auditLog(Number(c.req.query('limit') ?? 200))));

  app.route('/v1', v1);
  mountUi(app, ctx);
  app.get('/', (c) => c.redirect('/ui'));
  return app;
}
