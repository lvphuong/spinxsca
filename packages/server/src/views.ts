import {
  type BranchCell,
  branchMatrix,
  type Clock,
  evaluateReleaseGate,
  type GateResult,
  type ReleaseGatePolicy,
  scanBranch,
} from '@spinxsca/core';
import type {
  AgentRunRecord,
  Disposition,
  Evidence,
  Finding,
  FindingAssessment,
  FindingOccurrence,
} from '@spinxsca/schemas';
import type { ProjectEntry } from './registry';
import type { ProjectState } from './state';

export interface BranchSummary {
  branch: string;
  scanId: string;
  mode: string;
  status: string;
  completedAt?: string;
  open: number;
  fixed: number;
}

export interface FindingRow {
  findingId: string;
  title: string;
  category: string;
  cwe: string[];
  branches: Record<
    string,
    {
      state: BranchCell['state'];
      severity: string;
      scanId: string;
      carriedThrough?: string;
      kev?: boolean;
      epss?: number;
    }
  >;
}

export interface ProjectOverview {
  project: Omit<ProjectEntry, 'webhookSecret'>;
  branches: BranchSummary[];
  findings: FindingRow[];
}

export function publicProject(p: ProjectEntry): Omit<ProjectEntry, 'webhookSecret'> {
  const { webhookSecret: _secret, ...rest } = p;
  return rest;
}

export async function projectOverview(
  state: ProjectState,
  project: ProjectEntry,
  clock: Clock,
): Promise<ProjectOverview> {
  const engineProject = await state.engineProjectId();
  if (!engineProject) return { project: publicProject(project), branches: [], findings: [] };
  const matrix = await branchMatrix(state.repo, engineProject, clock.now());
  return {
    project: publicProject(project),
    branches: matrix.branches.map((b) => ({
      branch: b.branch,
      scanId: b.scan.scanId,
      mode: b.scan.mode,
      status: b.scan.status,
      ...(b.scan.completedAt ? { completedAt: b.scan.completedAt } : {}),
      open: b.open,
      fixed: b.fixed,
    })),
    findings: matrix.rows.map((r) => ({
      findingId: r.finding.findingId,
      title: r.finding.title,
      category: r.finding.category,
      cwe: r.finding.cwe,
      branches: cellsOf(r.cells),
    })),
  };
}

export interface FindingDetail {
  finding: Finding;
  branches: FindingRow['branches'];
  latest?: { occurrence: FindingOccurrence; evidence: Evidence[] };
  history: Array<FindingAssessment & { branch?: string; mode?: string }>;
  dispositions: Disposition[];
  explanation?: AgentRunRecord;
}

export async function findingDetail(
  state: ProjectState,
  findingId: string,
  clock: Clock,
): Promise<FindingDetail | undefined> {
  const finding = await state.repo.getFinding(findingId);
  if (!finding) return undefined;
  const matrix = await branchMatrix(state.repo, finding.projectId, clock.now());
  const row = matrix.rows.find((r) => r.finding.findingId === findingId);
  const occurrences = await state.repo.occurrencesForFinding(findingId);
  const occurrence = occurrences.at(-1);
  const scans = new Map<string, { branch?: string; mode: string }>();
  const history = [];
  for (const a of await state.repo.assessmentsForFinding(findingId)) {
    if (!scans.has(a.scanId)) {
      const scan = await state.repo.getScan(a.scanId);
      const branch = scan ? await scanBranch(state.repo, scan) : undefined;
      scans.set(a.scanId, { ...(branch ? { branch } : {}), mode: scan?.mode ?? 'UNKNOWN' });
    }
    history.push({ ...a, ...scans.get(a.scanId) });
  }
  history.sort((a, b) => b.assessedAt.localeCompare(a.assessedAt));
  const runs = await state.repo.listAgentRuns({ findingId });
  const explanation = runs.filter((r) => r.role === 'explain' && r.status === 'COMPLETED').at(-1);
  return {
    finding,
    branches: row ? cellsOf(row.cells) : {},
    ...(occurrence ? { latest: { occurrence, evidence: await state.repo.getEvidence(occurrence.evidenceIds) } } : {}),
    history,
    dispositions: (await state.repo.listDispositions(finding.projectId)).filter((d) => d.findingId === findingId),
    ...(explanation ? { explanation } : {}),
  };
}

function cellsOf(cells: Record<string, BranchCell>): FindingRow['branches'] {
  return Object.fromEntries(
    Object.entries(cells).map(([branch, c]) => [
      branch,
      {
        state: c.state,
        severity: c.severity,
        scanId: c.scanId,
        ...(c.carriedThrough ? { carriedThrough: c.carriedThrough } : {}),
        ...(c.assessment.intel?.kev ? { kev: true } : {}),
        ...(c.assessment.intel?.epss ? { epss: c.assessment.intel.epss.score } : {}),
      },
    ]),
  );
}

export async function gateFor(
  state: ProjectState,
  branch: string,
  policy: ReleaseGatePolicy,
  clock: Clock,
  kbSnapshotCreatedAt?: (id: string) => Promise<string | undefined>,
): Promise<GateResult> {
  const engineProject = await state.engineProjectId();
  if (!engineProject) {
    return {
      branch,
      passed: false,
      evaluatedAt: clock.now().toISOString(),
      policy,
      checks: [{ id: 'scan-exists', passed: false, message: 'project has never been scanned' }],
      blocking: [],
    };
  }
  return evaluateReleaseGate(state.repo, {
    projectId: engineProject,
    branch,
    policy,
    now: clock.now(),
    ...(kbSnapshotCreatedAt ? { kbSnapshotCreatedAt } : {}),
  });
}
