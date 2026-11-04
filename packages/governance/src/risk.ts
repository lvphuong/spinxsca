import { RISK_RANK, type RiskClass, TOOL_RISK } from '@spinxsca/schemas';

/** Risks that never leave the host process and the case store. */
export const LOW_RISKS: ReadonlySet<RiskClass> = new Set(['READ', 'RECORD', 'ANALYZE']);

/** Risks an agent may only reach through a human-approved `request_*` tool. */
export const REQUEST_ONLY_RISKS: ReadonlySet<RiskClass> = new Set(['WRITE_REPO', 'EXTERNAL', 'GOVERNANCE']);

export function maxRisk(...risks: Array<RiskClass | undefined>): RiskClass {
  let out: RiskClass = 'READ';
  for (const r of risks) if (r && RISK_RANK[r] > RISK_RANK[out]) out = r;
  return out;
}

/**
 * Effective risk of a tool: the catalog entry, raised by the tool's own declaration and by operator
 * overrides. Lowering is impossible, and a tool missing from the catalog is GOVERNANCE (fail closed).
 */
export function riskOf(
  tool: string,
  declared?: RiskClass,
  overrides: Readonly<Record<string, RiskClass>> = {},
): RiskClass {
  const catalog = TOOL_RISK[tool];
  if (!catalog) return maxRisk('GOVERNANCE', declared, overrides[tool]);
  return maxRisk(catalog, declared, overrides[tool]);
}

export function isRequestTool(tool: string): boolean {
  return tool.startsWith('request_') && TOOL_RISK[tool] !== undefined;
}

/** Where the effect of an action lands, for approval cards ("stays in the sandbox" vs "writes to your repo"). */
export function effectOf(risk: RiskClass): 'sandbox' | 'workspace' | 'repository' | 'external' | 'governance' {
  switch (risk) {
    case 'WRITE_WORKSPACE':
      return 'workspace';
    case 'WRITE_REPO':
      return 'repository';
    case 'EXTERNAL':
    case 'EGRESS':
      return 'external';
    case 'GOVERNANCE':
      return 'governance';
    default:
      return 'sandbox';
  }
}
