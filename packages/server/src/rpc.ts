/**
 * Repository calls a remote worker may make through the control plane (ADR-037). Human decisions
 * (dispositions, baselines) are never available to workers.
 */
export const READ_METHODS = [
  'getProject',
  'getSnapshot',
  'getScan',
  'listScans',
  'latestScan',
  'listTasks',
  'findReusableTask',
  'listCandidates',
  'getEvidence',
  'nextFindingSeq',
  'listFindings',
  'getFinding',
  'fingerprintIndex',
  'listOccurrences',
  'occurrencesForFinding',
  'listAssessments',
  'latestByFinding',
  'assessmentsForFinding',
  'listMatchEvents',
  'listDispositions',
  'activeBaseline',
  'listBaselines',
  'listAgentRuns',
] as const;
export const WRITE_METHODS = [
  'ensureProject',
  'saveSnapshot',
  'createScan',
  'updateScan',
  'upsertTask',
  'saveCandidates',
  'saveEvidence',
  'commitReconciliation',
  'saveAgentRun',
] as const;
export type RepositoryMethod = (typeof READ_METHODS)[number] | (typeof WRITE_METHODS)[number];
export const REPOSITORY_METHODS: ReadonlySet<string> = new Set([...READ_METHODS, ...WRITE_METHODS]);

/**
 * Case store calls a remote worker may make while running a REVIEW or CASE_RESUME job (ADR-047).
 * Writes are fenced like repository writes. Human operations are listed separately and are never
 * routed for a worker, whatever the job.
 */
export const CASE_READ_METHODS = [
  'getCase',
  'listCases',
  'listObjectives',
  'getWorkItem',
  'listWorkItems',
  'listJournal',
  'listAudit',
  'listAgentSteps',
  'getToolCall',
  'listToolCalls',
  'getApproval',
  'findApproval',
  'listApprovals',
  'listGrants',
  'getLedger',
  'listChecks',
  'listVerdicts',
  'listHandles',
  'listMemory',
] as const;
export const CASE_WRITE_METHODS = [
  'createCase',
  'updateCase',
  'saveObjectives',
  'saveWorkItem',
  'appendJournal',
  'appendAudit',
  'saveAgentStep',
  'saveToolCall',
  'createApproval',
  'chargeLedger',
  'saveCheck',
  'saveVerdict',
  'saveHandles',
  'saveMemory',
] as const;
/** Decisions only a human (through the API, CLI or desktop app) can make. */
export const CASE_HUMAN_METHODS = [
  'resolveApproval',
  'saveGrant',
  'revokeGrant',
  'updateMemoryStatus',
  'waiveObjective',
] as const;
export type CaseMethod = (typeof CASE_READ_METHODS)[number] | (typeof CASE_WRITE_METHODS)[number];
export const CASE_METHODS: ReadonlySet<string> = new Set([...CASE_READ_METHODS, ...CASE_WRITE_METHODS]);
export const CASE_WRITES: ReadonlySet<string> = new Set(CASE_WRITE_METHODS);

/** True when a worker may call the case method (never a human-only one). */
export function workerMayCall(method: string): method is CaseMethod {
  return CASE_METHODS.has(method) && !(CASE_HUMAN_METHODS as readonly string[]).includes(method);
}

/** JSON with Map and Set preserved (fingerprintIndex and latestByFinding return Maps). */
export function encode(value: unknown): string {
  return JSON.stringify(value, (_key, v) => {
    if (v instanceof Map) return { $map: [...v.entries()] };
    if (v instanceof Set) return { $set: [...v.values()] };
    return v;
  });
}

export function decode<T = unknown>(text: string): T {
  return JSON.parse(text, (_key, v) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const keys = Object.keys(v);
      if (keys.length === 1 && keys[0] === '$map' && Array.isArray(v.$map)) return new Map(v.$map);
      if (keys.length === 1 && keys[0] === '$set' && Array.isArray(v.$set)) return new Set(v.$set);
    }
    return v;
  }) as T;
}
