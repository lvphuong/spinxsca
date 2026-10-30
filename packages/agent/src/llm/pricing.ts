import type { Usage } from './types';

/** USD per million tokens. Cache writes are 1.25x input (5-minute TTL). Source: Anthropic pricing, 2026-09. */
const PRICES: Record<string, { input: number; output: number; cacheRead: number }> = {
  'claude-fable-5-1': { input: 10, output: 50, cacheRead: 0.25 },
  'claude-fable-5': { input: 10, output: 50, cacheRead: 1 },
  'claude-opus-5-5': { input: 4, output: 20, cacheRead: 0.2 },
  'claude-opus-5': { input: 5, output: 25, cacheRead: 0.5 },
  'claude-opus-4-8': { input: 5, output: 25, cacheRead: 0.5 },
  'claude-opus-4-7': { input: 5, output: 25, cacheRead: 0.5 },
  'claude-sonnet-5-5': { input: 2, output: 10, cacheRead: 0.2 },
  'claude-sonnet-5': { input: 2, output: 10, cacheRead: 0.2 },
  'claude-haiku-4-5': { input: 1, output: 5, cacheRead: 0.1 },
};

/** Cost of one response, or undefined for models without a known price (never guessed). */
export function costOf(usage: Usage, model: string): number | undefined {
  const price = PRICES[model];
  if (!price) return model === 'scripted' ? 0 : undefined;
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
