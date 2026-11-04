import type { RunRef, WorkItem, WorkItemKind, WorkItemStatus } from '@spinxsca/schemas';
import { SpinxscaError } from '../errors';

/** Who moves an item: the host conductor, the lead (board tools only) or a worker persona. */
export type BoardActor =
  | { kind: 'host' }
  | { kind: 'lead'; runId: string }
  | { kind: 'worker'; persona: string; runId: string };

export class AuthorityError extends SpinxscaError {
  constructor(message: string) {
    super(message, 'AUTHORITY');
    this.name = 'AuthorityError';
  }
}

const EDGES: Readonly<Record<WorkItemStatus, readonly WorkItemStatus[]>> = {
  todo: ['in_progress', 'blocked', 'cancelled'],
  in_progress: ['review', 'blocked', 'todo', 'cancelled'],
  blocked: ['todo', 'in_progress', 'cancelled'],
  review: ['done', 'in_progress', 'todo', 'cancelled'],
  done: [],
  cancelled: [],
};

export const TERMINAL_STATUSES: ReadonlySet<WorkItemStatus> = new Set(['done', 'cancelled']);

/** Kinds whose result counts only after an independent check by another persona and run. */
export const VERIFIED_KINDS: ReadonlySet<WorkItemKind> = new Set(['EXPLOIT_POC', 'FIX']);

/**
 * Separation of powers on the board (ADR-044), enforced in the store rather than in prompts:
 * workers move only their own items and never to done; the lead plans (cancels optional items,
 * re-queues blocked ones) but never executes or completes; only the host completes, and items of a
 * verified kind complete only after an independent verifier.
 */
export function checkTransition(item: WorkItem, to: WorkItemStatus, actor: BoardActor): void {
  const from = item.status;
  if (!EDGES[from].includes(to)) throw new AuthorityError(`illegal transition ${from} → ${to} for ${item.itemId}`);
  if (to === 'cancelled' && item.mandatory && actor.kind !== 'host') {
    throw new AuthorityError(`${item.itemId} is mandatory and cannot be cancelled`);
  }
  switch (actor.kind) {
    case 'host':
      if (to === 'done') {
        const gate = verificationGate(item);
        if (!gate.ok) throw new AuthorityError(gate.reason);
      }
      return;
    case 'lead': {
      const allowed =
        (from === 'todo' && to === 'cancelled') || (from === 'blocked' && (to === 'todo' || to === 'cancelled'));
      if (!allowed) throw new AuthorityError(`the lead cannot move ${item.itemId} ${from} → ${to}`);
      return;
    }
    case 'worker': {
      if (item.persona !== actor.persona) {
        throw new AuthorityError(`${item.itemId} is assigned to ${item.persona}, not ${actor.persona}`);
      }
      const allowed =
        (from === 'todo' && to === 'in_progress') ||
        (from === 'in_progress' && (to === 'review' || to === 'blocked')) ||
        (from === 'blocked' && to === 'in_progress');
      if (!allowed) throw new AuthorityError(`a worker cannot move ${item.itemId} ${from} → ${to}`);
      return;
    }
  }
}

/** review → done: the deliverable exists and, for verified kinds, an independent verifier passed it. */
export function verificationGate(item: WorkItem): { ok: true } | { ok: false; reason: string } {
  if (item.status !== 'review') return { ok: false, reason: `${item.itemId} is not in review` };
  if (item.result === undefined) return { ok: false, reason: `${item.itemId} has no deliverable` };
  if (!VERIFIED_KINDS.has(item.kind)) return { ok: true };
  // The host marks results that claim nothing (a PoC that did not trigger, a fix that failed).
  if ((item.result as { needsVerification?: boolean } | null)?.needsVerification === false) return { ok: true };
  if (!item.producer || !item.verifier) return { ok: false, reason: `${item.itemId} needs an independent verifier` };
  try {
    checkIndependence(item.producer, item.verifier);
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
  return { ok: true };
}

/** A check (validation, PoC review, fix verification) must come from another persona and another run. */
export function checkIndependence(producer: RunRef | undefined, checker: RunRef): void {
  if (!producer) return;
  if (producer.runId === checker.runId) throw new AuthorityError(`run ${checker.runId} cannot check its own work`);
  if (producer.persona === checker.persona) {
    throw new AuthorityError(`persona ${checker.persona} cannot check work produced by the same persona`);
  }
}

/** Items that can start: todo, with every dependency in a terminal state. */
export function readyItems(items: readonly WorkItem[]): WorkItem[] {
  const status = new Map(items.map((i) => [i.itemId, i.status]));
  return items.filter(
    (i) => i.status === 'todo' && i.dependsOn.every((d) => TERMINAL_STATUSES.has(status.get(d) ?? 'done')),
  );
}

/** Applies a host-built patch and a transition; the authority check sees the patched item. */
export function moveItem(
  item: WorkItem,
  to: WorkItemStatus,
  actor: BoardActor,
  now: Date,
  patch: Partial<WorkItem> = {},
): WorkItem {
  const candidate: WorkItem = { ...item, ...patch, status: item.status };
  checkTransition(candidate, to, actor);
  return { ...candidate, status: to, updatedAt: now.toISOString() };
}
