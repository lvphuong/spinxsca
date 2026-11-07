import type { ContextBudget } from './context-budget';

/**
 * Character budgets for the blocks a role's prompt is assembled from (ADR-053). Shares are relative
 * to the effective window, so a 32k local model receives proportionally smaller ground-truth,
 * census and digest blocks instead of the fixed sizes tuned for a 200k window.
 */
export type PromptRole =
  | 'recon'
  | 'investigator'
  | 'mapper'
  | 'reducer'
  | 'auditor'
  | 'critic'
  | 'lead'
  | 'worker'
  | 'explore';

export interface PromptBudget {
  /** Characters the whole dynamic part of the prompt may use. */
  total: number;
  groundTruth: number;
  census: number;
  digest: number;
  signals: number;
  operator: number;
  /** Lead only: board + journal + memory. */
  board: number;
  journal: number;
  memory: number;
}

const SHARE: Record<PromptRole, number> = {
  recon: 0.3,
  investigator: 0.25,
  mapper: 0.25,
  reducer: 0.45,
  auditor: 0.2,
  critic: 0.25,
  lead: 0.2,
  worker: 0.25,
  explore: 0.1,
};

export function promptBudgetFor(budget: ContextBudget, role: PromptRole): PromptBudget {
  const total = Math.floor(budget.effective * 4 * SHARE[role]);
  const part = (share: number, min: number) => Math.max(min, Math.floor(total * share));
  return {
    total,
    groundTruth: part(0.35, 1_500),
    census: part(0.15, 800),
    digest: part(0.2, 800),
    signals: part(0.15, 800),
    operator: part(0.05, 400),
    board: part(0.04, 1_000),
    journal: part(0.04, 1_000),
    memory: part(0.02, 500),
  };
}
