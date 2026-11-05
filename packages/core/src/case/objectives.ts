import {
  type CaseHandle,
  type CaseVerdict,
  type CoverageCheck,
  type Objective,
  type ObjectiveStatus,
  SEVERITY_RANK,
  type Severity,
  type WorkItem,
} from '@spinxsca/schemas';

export interface CaseState {
  items: readonly WorkItem[];
  verdicts: readonly CaseVerdict[];
  handles: readonly CaseHandle[];
  checks: readonly CoverageCheck[];
  /** Ground-truth coverage computed by the host from recon and audit deliverables (ADR-049). */
  groundTruthCoverage?: GroundTruthCoverage;
}

export interface GroundTruthCoverage {
  /** Invariant ids without a PASS/FAIL/UNKNOWN result yet. */
  invariantGaps: string[];
  invariantTotal: number;
  /** Family members (`FAM-n path:line`) without a hunt-log verdict yet. */
  memberGaps: string[];
  memberTotal: number;
}

/** Categories whose impact a sandboxed harness can observe deterministically (ADR-045). */
export const RUNTIME_VERIFIABLE_CATEGORIES: ReadonlySet<string> = new Set([
  'SQL_INJECTION',
  'COMMAND_INJECTION',
  'PATH_TRAVERSAL',
  'XSS',
  'CODE_INJECTION',
]);

/**
 * Objectives are falsifiable: each kind is a pure predicate over the case store. While the case runs
 * an unmet objective stays OPEN; when it stops (`final`) it becomes NOT_MET with the reason, never
 * silently dropped.
 */
export function evaluateObjective(
  objective: Objective,
  state: CaseState,
  final: boolean,
): { status: ObjectiveStatus; reason: string } {
  if (objective.status === 'WAIVED') return { status: 'WAIVED', reason: objective.reason ?? 'waived by a human' };
  const verdictOf = latestVerdicts(state.verdicts);
  const result = (gaps: string[], what: string): { status: ObjectiveStatus; reason: string } =>
    gaps.length === 0
      ? { status: 'MET', reason: `all ${what}` }
      : {
          status: final ? 'NOT_MET' : 'OPEN',
          reason: `${gaps.length} not ${what}: ${gaps.slice(0, 10).join(', ')}${gaps.length > 10 ? ', …' : ''}`,
        };

  switch (objective.kind) {
    case 'MANDATORY_DONE':
      return result(
        state.items.filter((i) => i.mandatory && i.status !== 'done').map((i) => i.itemId),
        'mandatory work items done',
      );
    case 'ALL_TRIAGED':
      return result(
        state.handles
          .filter((h) => {
            const v = verdictOf.get(h.handle);
            return !v || v.verdict === 'UNREVIEWED';
          })
          .map((h) => h.handle),
        'findings triaged',
      );
    case 'CONFIRMED_HAVE_EVIDENCE':
      return result(
        [...verdictOf.values()]
          .filter((v) => v.verdict === 'TRUE_POSITIVE')
          .filter(
            (v) =>
              v.evidence.length === 0 ||
              (v.severity !== undefined && SEVERITY_RANK[v.severity] >= SEVERITY_RANK.HIGH && !v.attackPath),
          )
          .map((v) => v.handle),
        'confirmed findings backed by evidence',
      );
    case 'DEPENDENCIES_ASSESSED':
      return result(
        state.handles
          .filter((h) => h.packagePurl)
          .filter((h) => {
            const status = verdictOf.get(h.handle)?.applicability?.status;
            return !status || status === 'UNDER_INVESTIGATION';
          })
          .map((h) => h.handle),
        'vulnerable dependencies assessed',
      );
    case 'COVERAGE_RECORDED': {
      const required = (objective.criteria.required as string[] | undefined) ?? [];
      const ids = new Set(state.checks.map((c) => c.checkId));
      const gaps = [
        ...state.checks.filter((c) => c.outcome === 'NOT_RUN').map((c) => c.checkId),
        ...required.filter((r) => !ids.has(r)),
      ];
      return result(gaps, 'coverage checks run');
    }
    case 'L3_ATTEMPTED': {
      const min = (objective.criteria.minSeverity as Severity | undefined) ?? 'HIGH';
      const handles = new Map(state.handles.map((h) => [h.handle, h]));
      return result(
        [...verdictOf.values()]
          .filter((v) => v.verdict === 'TRUE_POSITIVE' && !v.poc)
          .filter((v) => SEVERITY_RANK[v.severity ?? handles.get(v.handle)?.severity ?? 'INFO'] >= SEVERITY_RANK[min])
          .filter((v) => RUNTIME_VERIFIABLE_CATEGORIES.has(handles.get(v.handle)?.category ?? ''))
          .map((v) => v.handle),
        'runtime-verifiable confirmed findings with a PoC outcome',
      );
    }
    case 'INVARIANTS_CHECKED': {
      const cov = state.groundTruthCoverage;
      if (!cov) return { status: final ? 'NOT_MET' : 'OPEN', reason: 'no ground truth recorded yet' };
      if (cov.invariantTotal === 0) return { status: 'MET', reason: 'recon extracted no invariants' };
      return result(cov.invariantGaps, 'invariants checked');
    }
    case 'FAMILIES_SWEPT': {
      const cov = state.groundTruthCoverage;
      if (!cov) return { status: final ? 'NOT_MET' : 'OPEN', reason: 'no ground truth recorded yet' };
      if (cov.memberTotal === 0) return { status: 'MET', reason: 'recon extracted no variant families' };
      return result(cov.memberGaps, 'family members swept');
    }
    case 'CUSTOM': {
      const itemId = objective.criteria.itemId as string | undefined;
      const item = state.items.find((i) => i.itemId === itemId);
      if (item?.status === 'done') return { status: 'MET', reason: `${item.itemId} done` };
      return {
        status: final ? 'NOT_MET' : 'OPEN',
        reason: item ? `${item.itemId} is ${item.status}` : 'no work item linked to this objective',
      };
    }
  }
}

export function evaluateObjectives(
  objectives: readonly Objective[],
  state: CaseState,
  final: boolean,
  now: Date,
): Objective[] {
  return objectives.map((o) => {
    const { status, reason } = evaluateObjective(o, state, final);
    return { ...o, status, reason, evaluatedAt: now.toISOString() };
  });
}

/** Latest verdict per handle (later verdicts supersede earlier ones). */
export function latestVerdicts(verdicts: readonly CaseVerdict[]): Map<string, CaseVerdict> {
  const out = new Map<string, CaseVerdict>();
  for (const v of [...verdicts].sort((a, b) => a.at.localeCompare(b.at))) out.set(v.handle, v);
  return out;
}
