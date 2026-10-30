import type { Finding, FindingAssessment, ScanRun, Severity } from '@spinxsca/schemas';
import { severityAtLeast } from '@spinxsca/schemas';
import { scansByBranch } from './branches';
import { activeDispositions } from './policy';
import type { ScanRepository } from './ports';
import { PRESENT_STATES } from './reconcile';

export interface ReleaseGatePolicy {
  maxScanAgeHours: number;
  failOnSeverity: Severity;
  blockKev: boolean;
  epssThreshold?: number;
  requireCompleteCoverage: boolean;
  maxKbAgeHours?: number;
}

export const DEFAULT_GATE_POLICY: ReleaseGatePolicy = {
  maxScanAgeHours: 72,
  failOnSeverity: 'HIGH',
  blockKev: true,
  requireCompleteCoverage: true,
};

export interface GateCheck {
  id: 'scan-exists' | 'scan-age' | 'coverage' | 'severity' | 'kev' | 'epss' | 'kb-age';
  passed: boolean;
  message: string;
}

export interface GateResult {
  branch: string;
  passed: boolean;
  evaluatedAt: string;
  scan?: {
    scanId: string;
    status: ScanRun['status'];
    completedAt?: string;
    ageHours: number;
    coverage?: string;
    kbSnapshotId?: string;
  };
  checks: GateCheck[];
  blocking: Array<{ findingId: string; title: string; severity: Severity; reasons: string[] }>;
  policy: ReleaseGatePolicy;
}

/**
 * Release Security Gate (docs/architecture/05 section 4): evaluates the release state of a branch,
 * i.e. every open finding of its latest scan, not only new ones. A stale scan fails the gate because
 * "no findings" from an old scan says nothing about today's knowledge base.
 */
export async function evaluateReleaseGate(
  repo: ScanRepository,
  input: {
    projectId: string;
    branch: string;
    policy: ReleaseGatePolicy;
    now: Date;
    kbSnapshotCreatedAt?: (snapshotId: string) => Promise<string | undefined>;
  },
): Promise<GateResult> {
  const { policy, now, branch } = input;
  const base = { branch, evaluatedAt: now.toISOString(), policy };
  const scans = (await scansByBranch(repo, input.projectId)).get(branch) ?? [];
  const scan = scans[0];
  // Freshness is measured from the latest FULL scan: incremental and dependency-only scans do not
  // re-run every analyzer over the whole tree.
  const full = scans.find((s) => s.mode === 'FULL');
  if (!scan || !full) {
    return {
      ...base,
      passed: false,
      checks: [{ id: 'scan-exists', passed: false, message: `no completed full scan of branch ${branch}` }],
      blocking: [],
    };
  }
  const finishedAt = full.completedAt ?? full.requestedAt;
  const ageHours = (now.getTime() - Date.parse(finishedAt)) / 3_600_000;
  const checks: GateCheck[] = [
    {
      id: 'scan-exists',
      passed: true,
      message: `latest scan ${scan.scanId} (${scan.mode.toLowerCase().replace(/_/g, ' ')})`,
    },
  ];
  checks.push({
    id: 'scan-age',
    passed: ageHours <= policy.maxScanAgeHours,
    message: `last full scan ${full.scanId} is ${ageHours.toFixed(1)} h old (limit ${policy.maxScanAgeHours} h)`,
  });
  const coverage = scan.summary?.completeness;
  if (policy.requireCompleteCoverage) {
    checks.push({ id: 'coverage', passed: coverage === 'COMPLETE', message: `coverage ${coverage ?? 'unknown'}` });
  }
  const kbId = scan.manifest.knowledgeBase?.snapshotId;
  if (policy.maxKbAgeHours !== undefined) {
    const created = kbId ? await input.kbSnapshotCreatedAt?.(kbId) : undefined;
    const kbAge = created ? (now.getTime() - Date.parse(created)) / 3_600_000 : Number.POSITIVE_INFINITY;
    checks.push({
      id: 'kb-age',
      passed: kbAge <= policy.maxKbAgeHours,
      message: created
        ? `knowledge base snapshot ${kbId} is ${kbAge.toFixed(1)} h old (limit ${policy.maxKbAgeHours} h)`
        : 'scan used no knowledge base snapshot',
    });
  }

  const suppressed = activeDispositions(await repo.listDispositions(input.projectId), now);
  const findings = new Map<string, Finding>();
  const blocking: GateResult['blocking'] = [];
  const counts = { severity: 0, kev: 0, epss: 0 };
  for (const a of await repo.listAssessments(scan.scanId)) {
    if (!isOpen(a) || suppressed.has(a.findingId)) continue;
    const reasons: string[] = [];
    if (a.classification !== 'UNLIKELY' && severityAtLeast(a.severity, policy.failOnSeverity)) {
      reasons.push(`severity ${a.severity}`);
      counts.severity++;
    }
    if (policy.blockKev && a.intel?.kev) {
      reasons.push(`known exploited (CISA KEV since ${a.intel.kev.dateAdded})`);
      counts.kev++;
    }
    if (policy.epssThreshold !== undefined && (a.intel?.epss?.score ?? 0) >= policy.epssThreshold) {
      reasons.push(`EPSS ${a.intel?.epss?.score.toFixed(3)}`);
      counts.epss++;
    }
    if (reasons.length === 0) continue;
    const finding = findings.get(a.findingId) ?? (await repo.getFinding(a.findingId));
    if (finding) findings.set(a.findingId, finding);
    blocking.push({ findingId: a.findingId, title: finding?.title ?? a.findingId, severity: a.severity, reasons });
  }
  checks.push({
    id: 'severity',
    passed: counts.severity === 0,
    message: `${counts.severity} open finding(s) at or above ${policy.failOnSeverity}`,
  });
  if (policy.blockKev)
    checks.push({ id: 'kev', passed: counts.kev === 0, message: `${counts.kev} open finding(s) in CISA KEV` });
  if (policy.epssThreshold !== undefined) {
    checks.push({
      id: 'epss',
      passed: counts.epss === 0,
      message: `${counts.epss} open finding(s) with EPSS ≥ ${policy.epssThreshold}`,
    });
  }
  blocking.sort((a, b) => a.findingId.localeCompare(b.findingId));
  return {
    ...base,
    passed: checks.every((c) => c.passed),
    scan: {
      scanId: scan.scanId,
      status: scan.status,
      ...(scan.completedAt ? { completedAt: scan.completedAt } : {}),
      ageHours: Math.round(ageHours * 10) / 10,
      ...(coverage ? { coverage } : {}),
      ...(kbId ? { kbSnapshotId: kbId } : {}),
    },
    checks,
    blocking,
  };
}

/** NOT_REEVALUATED findings stay open for the gate: not seen is not fixed (ADR-006). */
function isOpen(a: FindingAssessment): boolean {
  return PRESENT_STATES.has(a.reconciliationState) || a.reconciliationState === 'NOT_REEVALUATED';
}
