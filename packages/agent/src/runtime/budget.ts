import type { Usage } from '../llm/types';

export interface PriceOverride {
  input: number;
  output: number;
  cache_read?: number;
}

/** Cost with operator price overrides (`ai.pricing`) taking precedence over the built-in table. */
export function costWithOverrides(
  base: (usage: Usage, model: string) => number | undefined,
  overrides: Readonly<Record<string, PriceOverride>> = {},
): (usage: Usage, model: string) => number | undefined {
  return (usage, model) => {
    const p = overrides[model];
    if (!p) return base(usage, model);
    return (
      (usage.inputTokens * p.input +
        usage.outputTokens * p.output +
        usage.cacheReadTokens * (p.cache_read ?? 0) +
        usage.cacheWriteTokens * p.input * 1.25) /
      1_000_000
    );
  };
}

export class UnpricedModelError extends Error {
  constructor(model: string) {
    super(
      `model ${model} has no known price; set ai.pricing or ai.autonomy.allow_unpriced to run it without a human attending`,
    );
    this.name = 'UnpricedModelError';
  }
}

/** Unattended runs refuse models whose cost cannot be bounded, unless the operator allows it. */
export function assertPriced(
  model: string,
  costOf: (usage: Usage, model: string) => number | undefined,
  options: { attended: boolean; allowUnpriced: boolean },
): void {
  if (options.attended || options.allowUnpriced) return;
  const probe = costOf({ inputTokens: 1, outputTokens: 1, cacheReadTokens: 0, cacheWriteTokens: 0 }, model);
  if (probe === undefined) throw new UnpricedModelError(model);
}
