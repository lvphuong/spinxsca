import type { ProviderCapabilities } from '../llm/types';
import type { AgentBudget } from './types';

/**
 * What one session may put in front of the model (ADR-053). Derived from the provider's declared
 * window, never from a constant, so a 32k local model and a 200k frontier model get the same loop
 * with different numbers.
 */
export interface ContextBudget {
  /** Context window in tokens. */
  window: number;
  /** Output tokens requested per turn: the smaller of what the model accepts and the run budget. */
  maxOutput: number;
  /** Window share held back for the answer. */
  reserveOutput: number;
  /** Tokens available for prompt + transcript. */
  effective: number;
  /** Safety margin under `effective` that absorbs estimation error. */
  buffer: number;
  /** Compaction starts once the estimated request exceeds this. */
  compactThreshold: number;
  /** Characters of one tool result shown inline; the rest goes to the result store (ADR-056). */
  inlineResultChars: number;
}

const clamp = (n: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, n));

export function contextBudgetFor(
  caps: Pick<ProviderCapabilities, 'maxContext' | 'maxOutput'>,
  budget: Pick<AgentBudget, 'maxOutputTokens'>,
): ContextBudget {
  const window = Math.max(4_096, caps.maxContext);
  const maxOutput = Math.max(256, Math.min(caps.maxOutput, budget.maxOutputTokens));
  const reserveOutput = Math.min(maxOutput, 20_000);
  const effective = Math.max(1_024, window - reserveOutput);
  const buffer = clamp(Math.round(effective * 0.08), 2_000, 13_000);
  return {
    window,
    maxOutput,
    reserveOutput,
    effective,
    buffer,
    compactThreshold: Math.max(512, effective - buffer),
    inlineResultChars: clamp(Math.round(effective * 4 * 0.08), 4_000, 64_000),
  };
}

/** `max_tokens` for a request whose input is estimated at `estimatedInput` tokens. */
export function clampMaxTokens(budget: ContextBudget, estimatedInput: number): number {
  return Math.max(1_024, Math.min(budget.maxOutput, budget.window - estimatedInput - 256));
}
