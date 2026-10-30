import type {
  AgentRunRecord,
  AiExplanation,
  Disposition,
  Evidence,
  Finding,
  FindingAssessment,
  FindingCandidate,
  FindingOccurrence,
  ScanRun,
  ScanTask,
  SourceSnapshot,
} from '@spinxsca/schemas';
import { SEVERITY_RANK } from '@spinxsca/schemas';
import { SpinxscaError } from '../errors';
import { activeDispositions } from '../policy';
import type { ProjectRecord, RepositoryRecord, ScanRepository } from '../ports';
import { PRESENT_STATES } from '../reconcile';

export interface ReportEntry {
  finding: Finding;
  assessment: FindingAssessment;
  /** Occurrence in this scan, or the latest known occurrence for findings no longer reported. */
  occurrence?: FindingOccurrence;
  candidates: FindingCandidate[];
  evidence: Evidence[];
  /** Active human disposition, if any. */
  disposition?: Disposition;
  /** AI explanation produced during this scan. */
  explanation?: { output: AiExplanation; run: AgentRunRecord };
}

export interface ScanReportModel {
  scan: ScanRun;
  baseline?: ScanRun;
  project: ProjectRecord;
  repository: RepositoryRecord;
  snapshot: SourceSnapshot;
  tasks: ScanTask[];
  present: ReportEntry[];
  /** Present findings with an active disposition (false positive, accepted risk, won't fix, duplicate). */
  suppressed: ReportEntry[];
  resolved: ReportEntry[];
  notReevaluated: ReportEntry[];
  aiRuns: AgentRunRecord[];
}

/** Builds the report from the system of record only; reports are never written by a model (ADR-022). */
export async function buildReportModel(repo: ScanRepository, scanId: string): Promise<ScanReportModel> {
  const scan = await repo.getScan(scanId);
  if (!scan) throw new SpinxscaError(`scan ${scanId} not found`, 'NOT_FOUND');
  const projectInfo = await repo.getProject();
  const snapshot = await repo.getSnapshot(scan.snapshotId);
  if (!projectInfo || !snapshot) throw new SpinxscaError('project or snapshot missing', 'NOT_FOUND');
  const baseline = scan.baselineScanId ? await repo.getScan(scan.baselineScanId) : undefined;

  const [assessments, occurrences, candidates, tasks] = await Promise.all([
    repo.listAssessments(scanId),
    repo.listOccurrences(scanId),
    repo.listCandidates(scanId),
    repo.listTasks(scanId),
  ]);
  const occurrenceById = new Map(occurrences.map((o) => [o.occurrenceId, o]));
  const candidateById = new Map(candidates.map((c) => [c.candidateId, c]));
  const latest = await repo.latestByFinding(scan.projectId);
  const dispositions = activeDispositions(await repo.listDispositions(scan.projectId), new Date());
  const aiRuns = await repo.listAgentRuns({ scanId });
  const explanations = new Map<string, { output: AiExplanation; run: AgentRunRecord }>();
  for (const run of aiRuns) {
    if (run.role === 'explain' && run.status === 'COMPLETED' && run.findingId && run.output) {
      explanations.set(run.findingId, { output: run.output as AiExplanation, run });
    }
  }

  // Findings no longer reported point at an occurrence from an earlier scan; load its candidates too.
  const candidatesByScan = new Map<string, Map<string, FindingCandidate>>([[scanId, candidateById]]);
  const candidatesFor = async (id: string): Promise<Map<string, FindingCandidate>> => {
    let map = candidatesByScan.get(id);
    if (!map) {
      map = new Map((await repo.listCandidates(id)).map((c) => [c.candidateId, c]));
      candidatesByScan.set(id, map);
    }
    return map;
  };
  const entries: ReportEntry[] = [];
  for (const assessment of assessments) {
    const finding = await repo.getFinding(assessment.findingId);
    if (!finding) continue;
    const occurrence = assessment.occurrenceId
      ? occurrenceById.get(assessment.occurrenceId)
      : ((await repo.occurrencesForFinding(finding.findingId)).at(-1) ?? latest.get(finding.findingId)?.occurrence);
    const pool = occurrence ? await candidatesFor(occurrence.scanId) : candidateById;
    const entryCandidates = (occurrence?.candidateIds ?? [])
      .map((id) => pool.get(id))
      .filter((c): c is FindingCandidate => c !== undefined);
    const evidence = await repo.getEvidence(occurrence?.evidenceIds ?? []);
    const disposition = dispositions.get(finding.findingId);
    const explanation = explanations.get(finding.findingId);
    entries.push({
      finding,
      assessment,
      ...(occurrence ? { occurrence } : {}),
      candidates: entryCandidates,
      evidence,
      ...(disposition ? { disposition } : {}),
      ...(explanation ? { explanation } : {}),
    });
  }
  const bySeverity = (a: ReportEntry, b: ReportEntry): number =>
    SEVERITY_RANK[b.assessment.severity] - SEVERITY_RANK[a.assessment.severity] ||
    a.finding.findingId.localeCompare(b.finding.findingId);

  return {
    scan,
    ...(baseline ? { baseline } : {}),
    project: projectInfo.project,
    repository: projectInfo.repository,
    snapshot,
    tasks,
    present: entries
      .filter((e) => PRESENT_STATES.has(e.assessment.reconciliationState) && !e.disposition)
      .sort(bySeverity),
    suppressed: entries
      .filter((e) => PRESENT_STATES.has(e.assessment.reconciliationState) && e.disposition)
      .sort(bySeverity),
    resolved: entries.filter((e) => e.assessment.reconciliationState === 'RESOLVED').sort(bySeverity),
    notReevaluated: entries.filter((e) => e.assessment.reconciliationState === 'NOT_REEVALUATED').sort(bySeverity),
    aiRuns,
  };
}
