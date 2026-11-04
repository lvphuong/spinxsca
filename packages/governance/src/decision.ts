import type { GrantScope, PolicyDecision, PolicyLayer, RiskClass } from '@spinxsca/schemas';

export function allow(
  layer: PolicyLayer,
  rule: string,
  risk: RiskClass,
  reason: string,
  flags: string[] = [],
): PolicyDecision {
  return { outcome: 'allow', layer, rule, risk, reason, humanOnly: false, offeredGrants: [], flags };
}

export function deny(
  layer: PolicyLayer,
  rule: string,
  risk: RiskClass,
  reason: string,
  flags: string[] = [],
): PolicyDecision {
  return { outcome: 'deny', layer, rule, risk, reason, humanOnly: false, offeredGrants: [], flags };
}

export function ask(
  layer: PolicyLayer,
  rule: string,
  risk: RiskClass,
  reason: string,
  options: { humanOnly?: boolean; offeredGrants?: GrantScope[]; flags?: string[] } = {},
): PolicyDecision {
  return {
    outcome: 'ask',
    layer,
    rule,
    risk,
    reason,
    humanOnly: options.humanOnly ?? false,
    offeredGrants: options.humanOnly ? ['once'] : (options.offeredGrants ?? ['once']),
    flags: options.flags ?? [],
  };
}

/** Generic message for a refusal; it never names the rule, the path or the approver (anti-probing). */
export const NOT_PERMITTED =
  'This action is not permitted here. Choose a different approach, or record the gap as deferred work.';

/**
 * What the agent is told about a policy denial. Layers are disclosed only as broad categories so an
 * agent steered by injected content cannot map the policy by probing it.
 */
export function agentMessage(decision: PolicyDecision): string {
  if (decision.outcome !== 'deny') return '';
  switch (decision.layer) {
    case 'L0':
      return decision.rule === 'admission.invalid_input'
        ? 'The tool input was invalid.'
        : 'This tool is not available to you.';
    case 'L4':
      return 'The target is outside the scope of this case.';
    case 'L5':
      return 'The budget for this kind of action is exhausted. Continue without it and record the gap as deferred.';
    case 'L3':
      return 'This action is not allowed in the current mode. Record it as deferred work.';
    default:
      return NOT_PERMITTED;
  }
}
