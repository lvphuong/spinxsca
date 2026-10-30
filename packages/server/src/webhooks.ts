import { createHmac } from 'node:crypto';
import { z } from 'zod';
import { safeEqual } from './registry';
import type { ScanPayload } from './worker';

export type WebhookOutcome =
  | { kind: 'ignored'; reason: string }
  | { kind: 'scan'; payload: ScanPayload; idempotencyKey: string };

const ZERO = /^0+$/;

// Lenient views of provider payloads: only the fields used here, everything optional.
const GithubBody = z.object({
  ref: z.string().optional(),
  after: z.string().optional(),
  deleted: z.boolean().optional(),
  action: z.string().optional(),
  number: z.number().optional(),
  pull_request: z
    .object({
      number: z.number().optional(),
      head: z.object({ sha: z.string().optional(), ref: z.string().optional() }).optional(),
      base: z.object({ sha: z.string().optional() }).optional(),
    })
    .optional(),
});
const GitlabBody = z.object({
  ref: z.string().optional(),
  after: z.string().optional(),
  checkout_sha: z.string().nullable().optional(),
  object_attributes: z
    .object({
      action: z.string().optional(),
      iid: z.number().optional(),
      source_branch: z.string().optional(),
      last_commit: z.object({ id: z.string().optional() }).optional(),
      diff_refs: z.object({ base_sha: z.string().optional() }).optional(),
    })
    .optional(),
});

export function verifyGithubSignature(secret: string, body: string, header: string | undefined): boolean {
  if (!header?.startsWith('sha256=')) return false;
  const expected = `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
  return safeEqual(expected, header);
}

/** GitHub push and pull_request events → scan jobs (docs/architecture/05 section 5). */
export function githubEvent(projectId: string, event: string | undefined, payload: unknown): WebhookOutcome {
  const parsed = GithubBody.safeParse(payload);
  if (!parsed.success) return { kind: 'ignored', reason: 'unrecognised payload' };
  const body = parsed.data;
  if (event === 'ping') return { kind: 'ignored', reason: 'ping' };
  if (event === 'push') {
    const ref = String(body.ref ?? '');
    if (!ref.startsWith('refs/heads/')) return { kind: 'ignored', reason: `not a branch push (${ref})` };
    if (body.deleted || ZERO.test(String(body.after ?? ''))) return { kind: 'ignored', reason: 'branch deleted' };
    const branch = ref.slice('refs/heads/'.length);
    const commit = String(body.after);
    return {
      kind: 'scan',
      payload: { branch, commit, mode: 'FULL', trigger: 'webhook' },
      idempotencyKey: `scan:${projectId}:${branch}:${commit}:full`,
    };
  }
  if (event === 'pull_request') {
    if (!['opened', 'synchronize', 'reopened'].includes(String(body.action)))
      return { kind: 'ignored', reason: `pull_request ${body.action}` };
    const pr = body.pull_request ?? {};
    const number = Number(pr.number ?? body.number);
    const head = String(pr.head?.sha ?? '');
    const base = String(pr.base?.sha ?? '');
    if (!number || !head || !base) return { kind: 'ignored', reason: 'pull_request without head/base' };
    const branch = String(pr.head?.ref ?? `pr-${number}`);
    return {
      kind: 'scan',
      payload: {
        branch,
        commit: head,
        mode: 'INCREMENTAL',
        diffBase: base,
        fetchRefs: [{ remote: `refs/pull/${number}/head`, local: `refs/spinxsca/pr/${number}` }],
        trigger: 'webhook',
      },
      idempotencyKey: `scan:${projectId}:${branch}:${head}:pr:${base}`,
    };
  }
  return { kind: 'ignored', reason: `event ${event ?? 'unknown'}` };
}

/** GitLab Push Hook and Merge Request Hook → scan jobs. */
export function gitlabEvent(projectId: string, event: string | undefined, payload: unknown): WebhookOutcome {
  const parsed = GitlabBody.safeParse(payload);
  if (!parsed.success) return { kind: 'ignored', reason: 'unrecognised payload' };
  const body = parsed.data;
  if (event === 'Push Hook') {
    const ref = String(body.ref ?? '');
    if (!ref.startsWith('refs/heads/')) return { kind: 'ignored', reason: `not a branch push (${ref})` };
    const commit = String(body.checkout_sha ?? body.after ?? '');
    if (!commit || ZERO.test(commit)) return { kind: 'ignored', reason: 'branch deleted' };
    const branch = ref.slice('refs/heads/'.length);
    return {
      kind: 'scan',
      payload: { branch, commit, mode: 'FULL', trigger: 'webhook' },
      idempotencyKey: `scan:${projectId}:${branch}:${commit}:full`,
    };
  }
  if (event === 'Merge Request Hook') {
    const mr = body.object_attributes ?? {};
    if (!['open', 'update', 'reopen'].includes(String(mr.action)))
      return { kind: 'ignored', reason: `merge request ${mr.action}` };
    const iid = Number(mr.iid);
    const head = String(mr.last_commit?.id ?? '');
    const base = String(mr.diff_refs?.base_sha ?? '');
    if (!iid || !head || !base) return { kind: 'ignored', reason: 'merge request without head/base' };
    const branch = String(mr.source_branch ?? `mr-${iid}`);
    return {
      kind: 'scan',
      payload: {
        branch,
        commit: head,
        mode: 'INCREMENTAL',
        diffBase: base,
        fetchRefs: [{ remote: `refs/merge-requests/${iid}/head`, local: `refs/spinxsca/mr/${iid}` }],
        trigger: 'webhook',
      },
      idempotencyKey: `scan:${projectId}:${branch}:${head}:mr:${base}`,
    };
  }
  return { kind: 'ignored', reason: `event ${event ?? 'unknown'}` };
}
