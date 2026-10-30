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
