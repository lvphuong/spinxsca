import { priceOf } from './catalog';
import type { Usage } from './types';

/** Cost of one response from the catalog price (ADR-053), or undefined for unpriced models (never guessed). */
export function costOf(usage: Usage, model: string): number | undefined {
  const price = priceOf(model);
  if (!price) return undefined;
  return (
    (usage.inputTokens * price.input +
      usage.outputTokens * price.output +
      usage.cacheReadTokens * price.cacheRead +
      usage.cacheWriteTokens * price.input * 1.25) /
    1_000_000
  );
}

/** Rough per-finding estimate shown before an AI scan: ~60k input (mostly cached) and ~6k output tokens. */
export function estimateExplainCost(model: string, findings: number): number | undefined {
  const one = costOf(
    { inputTokens: 20_000, outputTokens: 6_000, cacheReadTokens: 40_000, cacheWriteTokens: 8_000 },
    model,
  );
  return one === undefined ? undefined : one * findings;
}
