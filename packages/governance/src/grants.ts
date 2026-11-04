import type { Grant, RiskClass } from '@spinxsca/schemas';
import type { ApprovalRequest, ApprovalResolution } from './approval';
import { relPathOf, targetKey } from './targets';

/**
 * Turns a human approval with a `case` or `standing` scope into a grant. Only scopes that were
 * offered and validated by `validateGrant` produce one; standing rules bind the tool and the target
 * path (or "*"), case grants the exact target.
 */
export function grantFromApproval(
  request: ApprovalRequest,
  resolution: ApprovalResolution,
  input: { grantId: string; now: Date; standingTarget?: string },
): Grant | undefined {
  if (resolution.status !== 'approved' || resolution.by.kind !== 'human') return undefined;
  if (resolution.grant !== 'case' && resolution.grant !== 'standing') return undefined;
  if (request.humanOnly || !request.offeredGrants.includes(resolution.grant)) return undefined;
  const base = {
    grantId: input.grantId,
    projectId: request.projectId,
    tool: request.tool,
    risk: request.risk as RiskClass,
    createdBy: `human:${resolution.by.id}`,
    createdAt: input.now.toISOString(),
    ...(resolution.reason ? { reason: resolution.reason } : {}),
  };
  if (resolution.grant === 'case') {
    return { ...base, scope: 'case', caseId: request.caseId, target: targetKey(request.targets) };
  }
  const first = request.targets[0];
  const rel = first ? relPathOf(first) : undefined;
  return { ...base, scope: 'standing', target: input.standingTarget ?? rel ?? '*' };
}
