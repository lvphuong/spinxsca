import type { AgentRunRecord, AiAnswer, FindingCandidate, ScanRun, SnapshotFile } from '@spinxsca/schemas';
import { SpinxscaError } from '../errors';
import type {
  ArtifactStore,
  ExplainOutcome,
  ExplainSubject,
  FindingExplainer,
  ScanRepository,
  SourceTree,
} from '../ports';
import { PRESENT_STATES } from '../reconcile';
import { secretSpans } from './run-scan';

export interface ExplainDeps {
  repo: ScanRepository;
  artifacts: ArtifactStore;
  source: SourceTree;
  explainer: FindingExplainer;
}

/**
 * Explains one recorded finding on demand. Refuses when the file changed since the scan, because the
 * explanation would cite lines that no longer match the stored evidence.
 */
export async function explainFinding(
  deps: ExplainDeps,
  findingId: string,
  signal?: AbortSignal,
): Promise<ExplainOutcome> {
  const subject = await loadSubject(deps, findingId);
  const outcome = await deps.explainer.explain(subject, deps.source, signal);
  await deps.repo.saveAgentRun(outcome.run);
  return outcome;
}

export async function loadSubject(deps: Omit<ExplainDeps, 'explainer'>, findingId: string): Promise<ExplainSubject> {
  const finding = await deps.repo.getFinding(findingId);
  if (!finding) throw new SpinxscaError(`finding ${findingId} not found`, 'NOT_FOUND');
  const occurrence = (await deps.repo.occurrencesForFinding(findingId)).at(-1);
  if (!occurrence) throw new SpinxscaError(`finding ${findingId} has no recorded occurrence`, 'NOT_FOUND');
  const scan = await deps.repo.getScan(occurrence.scanId);
  if (!scan) throw new SpinxscaError(`scan ${occurrence.scanId} not found`, 'NOT_FOUND');
  const context = await scanContext(deps, scan);
  const recorded = context.files.find((f) => f.path === occurrence.anchor.path);
  const current = (await deps.source.listFiles({ exclude: scan.manifest.scope.exclude })).find(
    (f) => f.path === occurrence.anchor.path,
  );
  if (recorded && current?.digest !== recorded.digest) {
    throw new SpinxscaError(
      `${occurrence.anchor.path} changed since scan ${scan.scanId}; re-scan before explaining`,
      'SOURCE_CHANGED',
    );
  }
  return {
    scan,
    finding,
    occurrence,
    candidates: context.candidates.filter((c) => occurrence.candidateIds.includes(c.candidateId)),
    evidence: await deps.repo.getEvidence(occurrence.evidenceIds),
    snapshotPaths: context.files.map((f) => f.path),
    related: context.related.filter((r) => r.findingId !== findingId),
    redactions: secretSpans(context.candidates),
  };
}

export interface AskSubject {
  question: string;
  scan?: ScanRun;
  focus?: ExplainSubject;
  snapshotPaths: readonly string[];
  findings: ExplainSubject['related'];
  redactions: ExplainSubject['redactions'];
}

/** Developer Assistant (docs/architecture/03 section 12). */
export interface ProjectAssistant {
  readonly info: FindingExplainer['info'];
  ask(
    subject: AskSubject,
    source: SourceTree,
    signal?: AbortSignal,
  ): Promise<{ answer?: AiAnswer; run: AgentRunRecord }>;
}

export async function askProject(
  deps: Omit<ExplainDeps, 'explainer'> & { assistant: ProjectAssistant },
  input: { question: string; findingId?: string },
  signal?: AbortSignal,
): Promise<{ answer?: AiAnswer; run: AgentRunRecord }> {
  const project = await deps.repo.getProject();
  const scan = project ? await deps.repo.latestScan(project.project.projectId, ['COMPLETED', 'PARTIAL']) : undefined;
  const context = scan ? await scanContext(deps, scan) : undefined;
  const focus = input.findingId ? await loadSubject(deps, input.findingId) : undefined;
  const snapshotPaths = context
    ? context.files.map((f) => f.path)
    : (await deps.source.listFiles({ exclude: [] })).map((f) => f.path);
  const outcome = await deps.assistant.ask(
    {
      question: input.question,
      ...(scan ? { scan } : {}),
      ...(focus ? { focus } : {}),
      snapshotPaths,
      findings: context?.related ?? [],
      redactions: context ? secretSpans(context.candidates) : [],
    },
    deps.source,
    signal,
  );
  await deps.repo.saveAgentRun(outcome.run);
  return outcome;
}

async function scanContext(deps: Omit<ExplainDeps, 'explainer'>, scan: ScanRun) {
  const snapshot = await deps.repo.getSnapshot(scan.snapshotId);
  const files: SnapshotFile[] =
    snapshot && (await deps.artifacts.has(snapshot.fileListDigest))
      ? JSON.parse(await deps.artifacts.getText(snapshot.fileListDigest))
      : [];
  const candidates: FindingCandidate[] = await deps.repo.listCandidates(scan.scanId);
  const occurrences = await deps.repo.listOccurrences(scan.scanId);
  const assessments = await deps.repo.listAssessments(scan.scanId);
  const occurrenceById = new Map(occurrences.map((o) => [o.occurrenceId, o]));
  const related: ExplainSubject['related'] = [];
  for (const a of assessments) {
    if (!PRESENT_STATES.has(a.reconciliationState) || !a.occurrenceId) continue;
    const finding = await deps.repo.getFinding(a.findingId);
    const loc = occurrenceById.get(a.occurrenceId)?.locations[0];
    related.push({
      findingId: a.findingId,
      title: finding?.title ?? '',
      category: finding?.category ?? 'OTHER',
      location: loc ? `${loc.path}:${loc.startLine}` : '',
    });
  }
  return { files, candidates, related };
}
