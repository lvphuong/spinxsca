import { join } from 'node:path';
import {
  answerContextQuestion,
  applyPatchToRepository,
  type CaseRepository,
  declineContextQuestion,
  isContextQuestion,
  newId,
} from '@spinxsca/core';
import { type ApprovalRequest, grantFromApproval, validateGrant } from '@spinxsca/governance';
import type { ApprovalRecord, GrantScope } from '@spinxsca/schemas';
import pc from 'picocolors';
import { type CommonOptions, currentUser, withEngine } from '../context';
import { CliError, EXIT, status, table } from '../ui';

export interface InboxOptions extends CommonOptions {
  server?: string;
  project?: string;
  grant?: string;
  reason?: string;
  /** `inbox answer`: the human answer to a review question and where it comes from (ADR-051). */
  answer?: string;
  provenance?: string;
}

function toRequest(a: ApprovalRecord): ApprovalRequest {
  return { ...a, targets: a.targets, offeredGrants: a.offeredGrants, flags: [] };
}

async function api(options: InboxOptions, method: string, path: string, body?: unknown): Promise<unknown> {
  const token = process.env.SPINXSCA_TOKEN;
  if (!token) throw new CliError('set SPINXSCA_TOKEN to an API token of the server');
  const res = await fetch(`${(options.server as string).replace(/\/+$/, '')}${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, ...(body ? { 'content-type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (res.status === 409)
    throw new CliError(
      `already resolved by someone else (${(json.approval as ApprovalRecord | undefined)?.status ?? 'unknown'})`,
    );
  if (!res.ok) throw new CliError(`server: HTTP ${res.status} ${String(json.error ?? '')}`);
  return json;
}

function print(list: Array<ApprovalRecord & { project?: { name: string } }>, json: boolean | undefined): void {
  if (json) console.log(JSON.stringify(list, null, 2));
  else if (list.length === 0) status('nothing is waiting for a decision');
  else
    console.log(
      table(
        ['Approval', 'Requested', 'Action', 'Tool / risk', 'Human only'],
        list.map((a) => [
          a.approvalId,
          a.requestedAt,
          `${a.project ? `[${a.project.name}] ` : ''}${a.title}`,
          `${a.tool} / ${a.risk}`,
          a.humanOnly ? 'yes' : '',
        ]),
      ),
    );
}

/** `spinxsca inbox`: approvals review cases are waiting for, locally or on a server (ADR-047). */
export async function inboxCommand(
  action: 'list' | 'show' | 'approve' | 'deny' | 'answer',
  approvalId: string | undefined,
  path: string | undefined,
  options: InboxOptions,
): Promise<number> {
  if (options.server) {
    if (action === 'list') {
      print(
        (
          (await api(options, 'GET', '/v1/inbox')) as {
            approvals: Array<ApprovalRecord & { project: { name: string } }>;
          }
        ).approvals,
        options.json,
      );
      return EXIT.OK;
    }
    if (!approvalId || !options.project) throw new CliError('give the approval id and --project <projectId>');
    if (action === 'show') {
      const list = ((await api(options, 'GET', '/v1/inbox')) as { approvals: ApprovalRecord[] }).approvals;
      const a = list.find((x) => x.approvalId === approvalId);
      if (!a) throw new CliError(`approval ${approvalId} is not pending`);
      showOne(a);
      return EXIT.OK;
    }
    if (action === 'answer' && (!options.answer || !options.provenance))
      throw new CliError('inbox answer needs --answer <text> and --provenance <text>');
    const result = await api(
      options,
      'POST',
      `/v1/projects/${encodeURIComponent(options.project)}/approvals/${encodeURIComponent(approvalId)}`,
      action === 'answer'
        ? { decision: 'answer', answer: options.answer, provenance: options.provenance }
        : {
            decision: action === 'approve' ? 'approve' : 'deny',
            grant: options.grant ?? 'once',
            ...(options.reason ? { reason: options.reason } : {}),
          },
    );
    if (options.json) console.log(JSON.stringify(result, null, 2));
    else
      status(
        `${action === 'approve' ? 'approved' : action === 'deny' ? 'denied' : 'answered'} ${approvalId}; the case resumes on the server`,
      );
    return EXIT.OK;
  }

  return withEngine(path, options, async (engine) => {
    const cases = engine.cases as CaseRepository | undefined;
    if (!cases) throw new CliError('no case store in this state directory');
    if (action === 'list') {
      print(await cases.listApprovals({ status: 'PENDING' }), options.json);
      return EXIT.OK;
    }
    if (!approvalId) throw new CliError('give the approval id');
    const a = await cases.getApproval(approvalId);
    if (!a) throw new CliError(`approval ${approvalId} not found`);
    if (action === 'show') {
      if (options.json) console.log(JSON.stringify(a, null, 2));
      else showOne(a);
      return EXIT.OK;
    }
    const user = currentUser();
    if (action === 'answer') {
      if (!options.answer || !options.provenance)
        throw new CliError('inbox answer needs --answer <text> and --provenance <text>');
      const outcome = await answerContextQuestion(cases, approvalId, {
        answer: options.answer,
        provenance: options.provenance,
        by: user,
        now: new Date(),
      }).catch((err: Error) => {
        throw new CliError(err.message);
      });
      if (options.json) console.log(JSON.stringify(outcome, null, 2));
      else
        status(
          `answered ${approvalId}; memory ${outcome.memory?.memoryId ?? '-'} recorded${outcome.retriaged.length ? `; re-triage queued for ${outcome.retriaged.join(', ')}: continue with spinxsca review ${path ?? '.'} --case ${a.caseId}` : ''}`,
        );
      return EXIT.OK;
    }
    if (isContextQuestion(a)) {
      if (action === 'approve') throw new CliError('a review question is answered, not approved: use inbox answer');
      const declined = await declineContextQuestion(cases, approvalId, {
        by: user,
        ...(options.reason ? { reason: options.reason } : {}),
        now: new Date(),
      }).catch((err: Error) => {
        throw new CliError(err.message);
      });
      status(`${declined.status.toLowerCase()} ${approvalId}; the question stays open in the case journal`);
      return EXIT.OK;
    }
    const checked = validateGrant(toRequest(a), {
      status: action === 'approve' ? 'approved' : 'denied',
      by: { kind: 'human', id: user },
      grant: (options.grant ?? 'once') as GrantScope,
    });
    const { won, approval } = await cases.resolveApproval(approvalId, {
      status: action === 'approve' ? 'APPROVED' : 'DENIED',
      resolvedBy: { kind: 'human', id: user },
      ...(action === 'approve' && checked.grant ? { grantScope: checked.grant } : {}),
      ...(options.reason ? { reason: options.reason } : {}),
      resolvedAt: new Date().toISOString(),
    });
    if (!won) throw new CliError(`approval ${approvalId} was already ${approval.status.toLowerCase()}`);
    await cases.appendAudit({
      caseId: a.caseId,
      stage: 'approval.resolved',
      actor: `human:${user}`,
      toolCallId: a.toolCallId,
      data: { approvalId, status: approval.status, grant: approval.grantScope ?? null, notes: checked.notes ?? [] },
    });
    if (approval.status === 'APPROVED') {
      const grant = grantFromApproval(toRequest(a), checked, { grantId: newId('grant'), now: new Date() });
      if (grant) await cases.saveGrant(grant);
      if (a.tool === 'request_apply') {
        const { patchId } = JSON.parse(a.argsPreview) as { patchId: string };
        const applied = applyPatchToRepository(engine.source, join(engine.stateDir, 'patches'), patchId);
        await cases.appendJournal({
          caseId: a.caseId,
          kind: 'DECISION',
          author: `human:${user}`,
          handles: [],
          refs: [],
          text: `Applied ${patchId} to ${applied.files.join(', ')}`,
        });
        status(`${pc.green('applied')} ${patchId} to ${applied.files.join(', ')}`);
        return EXIT.OK;
      }
    }
    status(
      `${approval.status.toLowerCase()} ${approvalId}${approval.status === 'APPROVED' ? `; continue with: spinxsca review ${path ?? '.'} --case ${a.caseId}` : ''}`,
    );
    return EXIT.OK;
  });
}

function showOne(a: ApprovalRecord): void {
  console.log(
    [
      pc.bold(a.title),
      `tool ${a.tool} · risk ${a.risk} · effect ${a.effect}${a.humanOnly ? pc.red(' · human only') : ''}`,
      `case ${a.caseId} · requested ${a.requestedAt} · grants offered: ${a.offeredGrants.join(', ')}`,
      a.summary,
      a.argsPreview,
      ...(a.diff ? [a.diff] : []),
    ]
      .filter(Boolean)
      .join('\n'),
  );
}
