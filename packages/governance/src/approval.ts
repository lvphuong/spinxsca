import type {
  ActionTarget,
  ApprovalRecord,
  ApproverKind,
  GrantScope,
  PolicyDecision,
  RiskClass,
} from '@spinxsca/schemas';
import { effectOf } from './risk';

/** What an approver sees: the action as the host describes it, never tool outputs or repository content. */
export interface ApprovalRequest {
  approvalId: string;
  projectId: string;
  caseId: string;
  toolCallId: string;
  tool: string;
  risk: RiskClass;
  /** Carried on every request: only a human may approve it, whatever approver is asked (ADR-041). */
  humanOnly: boolean;
  title: string;
  summary: string;
  effect: ApprovalRecord['effect'];
  targets: readonly ActionTarget[];
  argsPreview: string;
  diff?: string;
  offeredGrants: readonly GrantScope[];
  flags: readonly string[];
}

export interface ApprovalResolution {
  status: 'approved' | 'denied' | 'unsure' | 'parked';
  by: { kind: ApproverKind; id: string };
  grant?: GrantScope;
  /** Diagnostic reason (audit only). */
  reason?: string;
  /** Adjustments made by the host (human-only enforcement, refused grant). */
  notes?: string[];
}

export interface Approver {
  readonly kind: ApproverKind;
  readonly id: string;
  decide(request: ApprovalRequest, signal?: AbortSignal): Promise<ApprovalResolution>;
}

export function buildApprovalRequest(input: {
  approvalId: string;
  projectId: string;
  caseId: string;
  toolCallId: string;
  tool: string;
  decision: PolicyDecision;
  title: string;
  summary: string;
  targets: readonly ActionTarget[];
  argsPreview: string;
  diff?: string;
}): ApprovalRequest {
  return {
    approvalId: input.approvalId,
    projectId: input.projectId,
    caseId: input.caseId,
    toolCallId: input.toolCallId,
    tool: input.tool,
    risk: input.decision.risk,
    humanOnly: input.decision.humanOnly,
    title: input.title,
    summary: input.summary,
    effect: effectOf(input.decision.risk),
    targets: input.targets,
    argsPreview: input.argsPreview,
    ...(input.diff !== undefined ? { diff: input.diff } : {}),
    offeredGrants: input.decision.humanOnly ? ['once'] : input.decision.offeredGrants,
    flags: input.decision.flags,
  };
}

/**
 * Runs after every approver: a human-only request approved by anything but a human is not approved.
 * The resolution becomes "unsure", so the chain continues to a human or parks in the inbox.
 */
export function enforceHumanOnly(request: ApprovalRequest, resolution: ApprovalResolution): ApprovalResolution {
  if (!request.humanOnly || resolution.status !== 'approved' || resolution.by.kind === 'human') return resolution;
  return {
    status: 'unsure',
    by: resolution.by,
    reason: 'human-only action approved by a non-human approver',
    notes: [...(resolution.notes ?? []), 'human_only_enforced'],
  };
}

/** A grant beyond what was offered (or from a non-human) is refused and the approval stays "once". */
export function validateGrant(request: ApprovalRequest, resolution: ApprovalResolution): ApprovalResolution {
  if (resolution.status !== 'approved' || !resolution.grant || resolution.grant === 'once') return resolution;
  const offered = request.offeredGrants.includes(resolution.grant) && !request.humanOnly;
  if (offered && resolution.by.kind === 'human') return resolution;
  return { ...resolution, grant: 'once', notes: [...(resolution.notes ?? []), 'grant_refused'] };
}

/**
 * Asks approvers in order until one concludes (approved, denied or parked). Approver errors count as
 * "unsure". When nobody concludes, the action is denied (fail closed).
 */
export async function resolveApproval(
  request: ApprovalRequest,
  approvers: readonly Approver[],
  options: { signal?: AbortSignal; onResolution?: (r: ApprovalResolution) => void | Promise<void> } = {},
): Promise<{ final: ApprovalResolution; trail: ApprovalResolution[] }> {
  const trail: ApprovalResolution[] = [];
  for (const approver of approvers) {
    let r: ApprovalResolution;
    try {
      r = await approver.decide(request, options.signal);
    } catch (err) {
      r = {
        status: 'unsure',
        by: { kind: approver.kind, id: approver.id },
        reason: `approver failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    r = validateGrant(request, enforceHumanOnly(request, r));
    trail.push(r);
    await options.onResolution?.(r);
    if (r.status !== 'unsure') return { final: r, trail };
  }
  const final: ApprovalResolution = {
    status: 'denied',
    by: { kind: 'policy', id: 'fail-closed' },
    reason: 'no approver concluded',
  };
  trail.push(final);
  return { final, trail };
}

/** A human answering through a callback (TTY prompt, desktop dialog, test). */
export class CallbackApprover implements Approver {
  readonly kind = 'human' as const;

  constructor(
    readonly id: string,
    private readonly ask: (
      request: ApprovalRequest,
      signal?: AbortSignal,
    ) => Promise<{ approved: boolean; grant?: GrantScope; reason?: string } | undefined>,
  ) {}

  async decide(request: ApprovalRequest, signal?: AbortSignal): Promise<ApprovalResolution> {
    const answer = await this.ask(request, signal);
    if (!answer) return { status: 'unsure', by: { kind: 'human', id: this.id }, reason: 'no answer' };
    return {
      status: answer.approved ? 'approved' : 'denied',
      by: { kind: 'human', id: this.id },
      ...(answer.grant ? { grant: answer.grant } : {}),
      ...(answer.reason ? { reason: answer.reason } : {}),
    };
  }
}

/** Unattended runs: the request is stored in the durable inbox and the work item is parked. */
export class InboxApprover implements Approver {
  readonly kind = 'inbox' as const;
  readonly id = 'inbox';

  constructor(private readonly park: (request: ApprovalRequest) => Promise<void>) {}

  async decide(request: ApprovalRequest): Promise<ApprovalResolution> {
    await this.park(request);
    return { status: 'parked', by: { kind: 'inbox', id: this.id }, reason: 'waiting for a human in the inbox' };
  }
}
