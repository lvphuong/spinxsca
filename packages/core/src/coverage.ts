import type { Coverage, Finding, FindingOccurrence } from '@spinxsca/schemas';

export interface CoverageVerdict {
  proven: boolean;
  reason: string;
}

/** Answers whether the current scan's coverage proves a previously seen finding is absent (ADR-006). */
export interface CoverageOracle {
  provesAbsence(finding: Finding, lastOccurrence: FindingOccurrence | undefined): CoverageVerdict;
}

export interface TaskCoverage {
  scannerId: string;
  succeeded: boolean;
  coverage: Coverage | undefined;
  analyzedPaths: ReadonlySet<string>;
}

/** Rule ids in coverage may end with ".*" when a tool runs its whole built-in check set. */
export function ruleCovered(ids: readonly string[], ruleId: string): boolean {
  return ids.some((id) => id === ruleId || (id.endsWith('.*') && ruleId.startsWith(id.slice(0, -1))));
}

export function buildCoverageOracle(input: {
  snapshotPaths: ReadonlySet<string>;
  tasks: readonly TaskCoverage[];
}): CoverageOracle {
  return {
    provesAbsence(_finding, occurrence) {
      if (!occurrence) return { proven: false, reason: 'no previous occurrence recorded' };
      const path = occurrence.anchor.path;
      const failures: string[] = [];
      for (const ruleId of occurrence.ruleIds) {
        const covering = input.tasks.filter((t) => ruleCovered(t.coverage?.rules?.ids ?? [], ruleId));
        if (covering.length === 0) {
          failures.push(`rule ${ruleId} was not executed`);
          continue;
        }
        if (!input.snapshotPaths.has(path)) {
          return { proven: true, reason: `${path} no longer exists in the snapshot` };
        }
        const complete = covering.find(
          (t) => t.succeeded && t.coverage?.completeness === 'COMPLETE' && t.analyzedPaths.has(path),
        );
        if (complete) {
          return {
            proven: true,
            reason: `${complete.scannerId} analysed ${path} with rule ${ruleId} and did not report it`,
          };
        }
        failures.push(`no complete task analysed ${path} with rule ${ruleId}`);
      }
      return { proven: false, reason: failures.join('; ') || 'no covering task' };
    },
  };
}
