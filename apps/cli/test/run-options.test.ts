import { SpinxscaConfig } from '@spinxsca/schemas';
import { describe, expect, it } from 'vitest';
import { applyRunOptions, autonomyConfig, enabledScanners, reviewDefaults } from '../src/autonomy';
import type { LoadedConfig } from '../src/config';

const loaded = (raw: Record<string, unknown> = {}): LoadedConfig => ({
  config: SpinxscaConfig.parse({ version: 1, ...raw }),
});
const base = autonomyConfig(
  loaded({ ai: { level: 'deep', autonomy: { mode: 'supervised', budgets: { max_cost_usd: 8, max_rounds: 6 } } } }),
  { unattended: true },
  8,
);

describe('review run options (ADR-052)', () => {
  it('only narrows budgets, rounds, time and mode', () => {
    const narrowed = applyRunOptions(base, { maxCostUsd: 2, maxRounds: 3, maxWallClockMin: 15, mode: 'observe' });
    expect(narrowed).toMatchObject({ maxCostUsd: 2, maxRounds: 3, maxWallClockMin: 15, mode: 'observe' });
    const looser = applyRunOptions(base, { maxCostUsd: 500, maxRounds: 99, maxWallClockMin: 1000, mode: 'autonomous' });
    expect(looser).toMatchObject({
      maxCostUsd: base.maxCostUsd,
      maxRounds: base.maxRounds,
      maxWallClockMin: base.maxWallClockMin,
      mode: 'supervised',
    });
    expect(applyRunOptions(base, undefined)).toBe(base);
  });

  it('switches proofs of concept, recon and critic passes, and appends accepted risks', () => {
    const o = applyRunOptions(base, {
      l3: true,
      recon: false,
      criticPasses: 0,
      acceptedRisks: ['Admins can export every tenant for billing.'],
    });
    expect(o.l3).toBe(true);
    expect(o.recon).toMatchObject({ enabled: false, criticPasses: 0 });
    expect(o.context?.accepted_risks).toEqual(['Admins can export every tenant for billing.']);
    expect(applyRunOptions(o, { l3: false }).l3).toBe(false);
  });

  it('reports defaults and enabled scanners, or why reviews are unavailable', () => {
    const cfg = loaded({ scan: { scanners: { trivy: { enabled: false } } }, ai: { level: 'deep' } });
    expect(enabledScanners(cfg.config)).toEqual(['semgrep', 'osv-scanner', 'gitleaks']);
    expect(reviewDefaults(cfg, null)).toMatchObject({
      available: false,
      scanners: ['semgrep', 'osv-scanner', 'gitleaks'],
    });
    const ai = {
      provider: 'scripted' as const,
      effort: 'high' as const,
      refusalFallback: 'default' as const,
      maxCostUsdPerFinding: 4,
      maxCostUsd: 4,
    };
    expect(reviewDefaults(cfg, ai)).toMatchObject({
      available: true,
      mode: 'supervised',
      maxCostUsd: 4,
      recon: true,
      criticPasses: 1,
      provider: 'scripted',
    });
  });
});
