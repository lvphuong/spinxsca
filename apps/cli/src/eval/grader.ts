import type { DetectionLayer, EvalCase } from '@spinxsca/schemas';

export const LINE_TOLERANCE = 2;

export interface ReportedFinding {
  findingId: string;
  category: string;
  cwe: string[];
  path: string;
  startLine: number;
  endLine: number;
  /** Advisory ids and aliases for dependency findings. */
  vulnerabilityIds?: string[];
}

type GroundTruth = EvalCase['findings'][number];

export interface CaseGrade {
  truePositives: Array<{ truth: GroundTruth; finding: ReportedFinding }>;
  falsePositives: Array<{ finding: ReportedFinding; negative?: string }>;
  falseNegatives: GroundTruth[];
  /** Ground truth expected only in a later phase; excluded from precision and recall. */
  pending: GroundTruth[];
}

/**
 * Deterministic grader (docs/architecture/07): a finding matches ground truth when the path is equal,
 * the lines overlap within a small tolerance and the category or a CWE agrees. Each side matches at
 * most once; findings matching pending ground truth are neither true nor false positives.
 */
export function gradeCase(evalCase: EvalCase, findings: readonly ReportedFinding[], phase: number): CaseGrade {
  const active = evalCase.findings.filter((g) => g.min_phase <= phase);
  const pending = evalCase.findings.filter((g) => g.min_phase > phase);
  const grade: CaseGrade = { truePositives: [], falsePositives: [], falseNegatives: [], pending };
  const usedFindings = new Set<string>();

  for (const truth of active) {
    const match = findings
      .filter((f) => !usedFindings.has(f.findingId) && matches(truth, f))
      .sort((a, b) => distance(truth, a) - distance(truth, b))[0];
    if (match) {
      usedFindings.add(match.findingId);
      grade.truePositives.push({ truth, finding: match });
    } else grade.falseNegatives.push(truth);
  }
  for (const finding of findings) {
    if (usedFindings.has(finding.findingId)) continue;
    if (pending.some((g) => matches(g, finding))) continue;
    const negative = evalCase.negatives.find(
      (n) => n.path === finding.path && (!n.lines || overlaps(n.lines, finding.startLine, finding.endLine, 0)),
    );
    grade.falsePositives.push({ finding, ...(negative ? { negative: negative.reason } : {}) });
  }
  return grade;
}

export function layersOf(truth: GroundTruth): DetectionLayer[] {
  return truth.detectable_by;
}

/** Layer a ground truth is graded under: its first non-AI detector, else AI. */
export function truthLayer(truth: GroundTruth): DetectionLayer {
  return truth.detectable_by.find((l) => l !== 'ai') ?? 'ai';
}

/** Layer that produced a reported finding, from its category. */
export function findingLayer(finding: ReportedFinding): DetectionLayer {
  if (finding.category === 'VULNERABLE_DEPENDENCY') return 'sca';
  if (finding.category === 'HARDCODED_SECRET') return 'secrets';
  if (finding.category === 'INSECURE_CONFIGURATION') return 'iac';
  return 'sast';
}

function matches(truth: GroundTruth, finding: ReportedFinding): boolean {
  if (truth.path !== finding.path) return false;
  if (!overlaps(truth.lines, finding.startLine, finding.endLine, LINE_TOLERANCE)) return false;
  if (truth.vulnerability_id && !(finding.vulnerabilityIds ?? []).includes(truth.vulnerability_id)) return false;
  return truth.category === finding.category || truth.cwe.some((c) => finding.cwe.includes(c));
}

function overlaps(range: readonly [number, number], start: number, end: number, tolerance: number): boolean {
  return start <= range[1] + tolerance && end >= range[0] - tolerance;
}

function distance(truth: GroundTruth, finding: ReportedFinding): number {
  return Math.abs(finding.startLine - truth.lines[0]);
}
