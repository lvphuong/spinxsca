import { TERMINAL_STATUSES } from '@spinxsca/core';
import type { WorkItem } from '@spinxsca/schemas';

export type CaseStop = 'CONVERGED' | 'STAGNATED' | 'BUDGET_EXHAUSTED' | 'PARKED' | 'PAUSED' | 'CANCELLED';

/**
 * When a case stops (ADR-044): all agent work terminal (CONVERGED), two rounds without progress
 * (STAGNATED), a budget or the round limit reached (BUDGET_EXHAUSTED), waiting for a human with
 * nothing else runnable (PARKED), paused by the operator (PAUSED, resumable; ADR-052), or cancelled.
 * Unmet objectives and unfinished mandatory items are then reported with reasons, never dropped.
 */
export function decideStop(s: {
  items: readonly WorkItem[];
  round: number;
  maxRounds: number;
  roundsWithoutProgress: number;
  parkedItems: ReadonlySet<string>;
  cancelled: boolean;
  /** The operator paused the case: stop now, keep in-progress work resumable. */
  paused?: boolean;
  /** Who asked, for the stop reason. */
  by?: string;
  budgetReason?: string;
}): { stop: CaseStop; reason: string } | undefined {
  if (s.paused) return { stop: 'PAUSED', reason: `paused by ${s.by ?? 'the operator'}` };
  if (s.cancelled) return { stop: 'CANCELLED', reason: `cancelled by ${s.by ?? 'the operator'}` };
  if (s.budgetReason) return { stop: 'BUDGET_EXHAUSTED', reason: s.budgetReason };
  const open = s.items.filter((i) => !TERMINAL_STATUSES.has(i.status) && i.persona !== 'host');
  if (open.length === 0) return { stop: 'CONVERGED', reason: 'every work item is finished' };
  const runnable = open.filter((i) => !s.parkedItems.has(i.itemId) && i.status !== 'blocked');
  if (runnable.length === 0 && s.parkedItems.size > 0)
    return { stop: 'PARKED', reason: `${s.parkedItems.size} item(s) wait for a human` };
  if (runnable.length === 0) return { stop: 'STAGNATED', reason: `${open.length} item(s) blocked` };
  if (s.roundsWithoutProgress >= 2) return { stop: 'STAGNATED', reason: 'two rounds without progress' };
  if (s.round >= s.maxRounds) return { stop: 'BUDGET_EXHAUSTED', reason: `round limit ${s.maxRounds} reached` };
  return undefined;
}
