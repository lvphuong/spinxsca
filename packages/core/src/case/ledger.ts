import type { CaseLedger } from '@spinxsca/schemas';

export interface LedgerDelta {
  costUsd?: number;
  inputTokens?: number;
  outputTokens?: number;
  modelCalls?: number;
  sandboxRuns?: number;
  sandboxCpuSec?: number;
  /** Handle whose validation-run count increases by one. */
  validationRunFor?: string;
  unpriced?: boolean;
}

export interface CaseLimits {
  maxCostUsd?: number;
  maxSandboxRuns?: number;
  maxSandboxCpuSec?: number;
  maxRunsPerFinding?: number;
}

export function emptyLedger(caseId: string, now: Date): CaseLedger {
  return {
    caseId,
    costUsd: 0,
    inputTokens: 0,
    outputTokens: 0,
    modelCalls: 0,
    sandboxRuns: 0,
    sandboxCpuSec: 0,
    validationRuns: {},
    unpriced: false,
    updatedAt: now.toISOString(),
  };
}

export function applyLedgerDelta(ledger: CaseLedger, d: LedgerDelta, now: Date): CaseLedger {
  const validationRuns = { ...ledger.validationRuns };
  if (d.validationRunFor) validationRuns[d.validationRunFor] = (validationRuns[d.validationRunFor] ?? 0) + 1;
  return {
    ...ledger,
    costUsd: ledger.costUsd + (d.costUsd ?? 0),
    inputTokens: ledger.inputTokens + (d.inputTokens ?? 0),
    outputTokens: ledger.outputTokens + (d.outputTokens ?? 0),
    modelCalls: ledger.modelCalls + (d.modelCalls ?? 0),
    sandboxRuns: ledger.sandboxRuns + (d.sandboxRuns ?? 0),
    sandboxCpuSec: ledger.sandboxCpuSec + (d.sandboxCpuSec ?? 0),
    validationRuns,
    unpriced: ledger.unpriced || (d.unpriced ?? false),
    updatedAt: now.toISOString(),
  };
}

/** Quota view of the ledger for the policy engine (L5). */
export function quotaOf(
  ledger: CaseLedger,
  limits: CaseLimits,
  handle?: string,
): {
  costUsd: number;
  maxCostUsd?: number;
  sandboxRuns: number;
  maxSandboxRuns?: number;
  sandboxCpuSec: number;
  maxSandboxCpuSec?: number;
  validationRunsForTarget?: number;
  maxRunsPerFinding?: number;
} {
  return {
    costUsd: ledger.costUsd,
    sandboxRuns: ledger.sandboxRuns,
    sandboxCpuSec: ledger.sandboxCpuSec,
    ...(limits.maxCostUsd !== undefined ? { maxCostUsd: limits.maxCostUsd } : {}),
    ...(limits.maxSandboxRuns !== undefined ? { maxSandboxRuns: limits.maxSandboxRuns } : {}),
    ...(limits.maxSandboxCpuSec !== undefined ? { maxSandboxCpuSec: limits.maxSandboxCpuSec } : {}),
    ...(handle ? { validationRunsForTarget: ledger.validationRuns[handle] ?? 0 } : {}),
    ...(limits.maxRunsPerFinding !== undefined ? { maxRunsPerFinding: limits.maxRunsPerFinding } : {}),
  };
}
