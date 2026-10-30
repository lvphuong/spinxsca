import type { Finding, FindingAssessment, ScanRun, Severity } from '@spinxsca/schemas';
import { activeDispositions } from './policy';
import type { ScanRepository } from './ports';
import { PRESENT_STATES } from './reconcile';

const SETTLED: readonly ScanRun['status'][] = ['COMPLETED', 'PARTIAL'];
const HISTORY_LIMIT = 500;

/** Branch a scan is attributed to: recorded in the manifest, else the git branch at capture. */
export async function scanBranch(repo: ScanRepository, scan: ScanRun): Promise<string | undefined> {
  if (scan.manifest.source.branch) return scan.manifest.source.branch;
  return (await repo.getSnapshot(scan.snapshotId))?.branchAtCapture;
}

/** Settled scans grouped by branch, newest first. Scans without a branch are grouped under "(none)". */
export async function scansByBranch(repo: ScanRepository, projectId: string): Promise<Map<string, ScanRun[]>> {
  const out = new Map<string, ScanRun[]>();
  const scans = (await repo.listScans(projectId, HISTORY_LIMIT))
    .filter((s) => SETTLED.includes(s.status))
    .sort((a, b) => (b.completedAt ?? b.requestedAt).localeCompare(a.completedAt ?? a.requestedAt));
  for (const scan of scans) {
    const branch = (await scanBranch(repo, scan)) ?? '(none)';
    out.set(branch, [...(out.get(branch) ?? []), scan]);
  }
  return out;
}

export async function latestScanOnBranch(
  repo: ScanRepository,
  projectId: string,
  branch: string,
): Promise<ScanRun | undefined> {
  return (await scansByBranch(repo, projectId)).get(branch)?.[0];
}

export type BranchFindingState = 'OPEN' | 'FIXED' | 'NOT_REEVALUATED' | 'SUPPRESSED';

export interface BranchCell {
  state: BranchFindingState;
  severity: Severity;
  /** Scan whose assessment decided the state. */
  scanId: string;
  assessment: FindingAssessment;
  /** Set when newer scans of the branch did not re-evaluate the finding (e.g. dependency-only reassessment). */
  carriedThrough?: string;
}

export interface BranchMatrix {
  branches: Array<{ branch: string; scan: ScanRun; open: number; fixed: number }>;
  rows: Array<{ finding: Finding; cells: Record<string, BranchCell> }>;
}

/**
 * Status of every finding on every branch (y-tuong: SEC-001 FIXED on main, OPEN on develop). The
 * cell comes from the newest assessment of the finding among the branch's scans, so a finding fixed
 * several scans ago is still shown as FIXED on that branch.
 */
export async function branchMatrix(repo: ScanRepository, projectId: string, now = new Date()): Promise<BranchMatrix> {
  const grouped = await scansByBranch(repo, projectId);
  const findings = new Map((await repo.listFindings(projectId)).map((f) => [f.findingId, f]));
  const suppressed = activeDispositions(await repo.listDispositions(projectId), now);
  const rows = new Map<string, Record<string, BranchCell>>();
  const branches: BranchMatrix['branches'] = [];
  for (const [branch, scans] of grouped) {
    const decided = new Set<string>();
    // Newest NOT_REEVALUATED assessment per finding, used when no older scan decided it.
    const pending = new Map<string, { scanId: string; assessment: FindingAssessment }>();
    const put = (assessment: FindingAssessment, scanId: string, state: BranchFindingState, carriedThrough?: string) => {
      const cells = rows.get(assessment.findingId) ?? {};
      cells[branch] = {
        state,
        severity: assessment.severity,
        scanId,
        assessment,
        ...(carriedThrough ? { carriedThrough } : {}),
      };
      rows.set(assessment.findingId, cells);
    };
    for (const scan of scans) {
      for (const assessment of await repo.listAssessments(scan.scanId)) {
        if (decided.has(assessment.findingId)) continue;
        if (assessment.reconciliationState === 'NOT_REEVALUATED') {
          if (!pending.has(assessment.findingId))
            pending.set(assessment.findingId, { scanId: scan.scanId, assessment });
          continue;
        }
        decided.add(assessment.findingId);
        const state: BranchFindingState = PRESENT_STATES.has(assessment.reconciliationState)
          ? suppressed.has(assessment.findingId)
            ? 'SUPPRESSED'
            : 'OPEN'
          : 'FIXED';
        put(assessment, scan.scanId, state, pending.get(assessment.findingId)?.scanId);
      }
    }
    for (const [findingId, p] of pending) if (!decided.has(findingId)) put(p.assessment, p.scanId, 'NOT_REEVALUATED');
    let open = 0;
    let fixed = 0;
    for (const cells of rows.values()) {
      if (cells[branch]?.state === 'OPEN') open++;
      if (cells[branch]?.state === 'FIXED') fixed++;
    }
    branches.push({ branch, scan: scans[0] as ScanRun, open, fixed });
  }
  branches.sort((a, b) => a.branch.localeCompare(b.branch));
  return {
    branches,
    rows: [...rows.entries()]
      .map(([id, cells]) => ({ finding: findings.get(id) as Finding, cells }))
      .filter((r) => r.finding)
      .sort((a, b) => a.finding.findingId.localeCompare(b.finding.findingId)),
  };
}
