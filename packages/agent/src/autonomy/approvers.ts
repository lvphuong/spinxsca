import {
  type ApprovalRequest,
  type Approver,
  CallbackApprover,
  type ConsecutiveBreaker,
  InboxApprover,
  type JudgeModel,
  type KnownWorld,
  ReviewerApprover,
  type ReviewerEvent,
} from '@spinxsca/governance';
import type { AutonomyMode, GrantScope, ReviewerMode } from '@spinxsca/schemas';

export type HumanApprover = (
  request: ApprovalRequest,
  signal?: AbortSignal,
) => Promise<{ approved: boolean; grant?: GrantScope; reason?: string } | undefined>;

/**
 * Approver chain of a case (ADR-041). The reviewer model is used only in autonomous mode while a
 * human is attending (never unattended); a human callback answers attended asks; whatever is left
 * parks in the durable inbox. Human-only requests skip the reviewer and are re-checked after every
 * approver by the governance pipeline.
 */
export function approverChain(o: {
  mode: AutonomyMode;
  attended: boolean;
  reviewer: ReviewerMode;
  judge?: JudgeModel;
  world: KnownWorld;
  breaker: ConsecutiveBreaker;
  human?: HumanApprover;
  park: (request: ApprovalRequest) => Promise<void>;
  onReviewerEvent?: (event: ReviewerEvent) => void | Promise<void>;
}): Approver[] {
  const chain: Approver[] = [];
  if (o.mode === 'autonomous' && o.attended && o.reviewer !== 'off' && o.judge) {
    chain.push(
      new ReviewerApprover({
        model: o.judge,
        mode: o.reviewer,
        world: o.world,
        breaker: o.breaker,
        ...(o.onReviewerEvent ? { onEvent: o.onReviewerEvent } : {}),
      }),
    );
  }
  if (o.attended && o.human) chain.push(new CallbackApprover('operator', o.human));
  chain.push(new InboxApprover(o.park));
  return chain;
}
