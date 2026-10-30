import { join } from 'node:path';
import type {
  Coverage,
  Evidence,
  Finding,
  FindingAssessment,
  FindingCandidate,
  Location,
  ScanMode,
  ScanRun,
  ScanStatus,
  ScanSummary,
  ScanTask,
  SnapshotFile,
} from '@spinxsca/schemas';
import { familyOf, Location as LocationSchema, SEVERITY_RANK } from '@spinxsca/schemas';
import { type Activity, runActivity } from '../activity';
import { latestScanOnBranch } from '../branches';
import { buildCauseAttributor } from '../causes';
import { buildCoverageOracle, type TaskCoverage } from '../coverage';
import { errorMessage, SpinxscaError, throwIfAborted } from '../errors';
import { anchorFor, assignInstances, semanticFingerprint } from '../fingerprint';
import { digestOf, newId, sha256Hex } from '../ids';
import { buildManifest } from '../manifest';
import type {
  ArtifactStore,
  CandidateDraft,
  Clock,
  CodeGraphView,
  CodeImpactReport,
  CodeIntelPort,
  ExplainSubject,
  FindingExplainer,
  Investigator,
  KnowledgeBasePort,
  KnowledgeBaseRef,
  Logger,
  SandboxRunner,
  ScannerAdapter,
  ScannerResult,
  ScanRepository,
  SourceTree,
} from '../ports';
import { groupCandidates, PRESENT_STATES, type PriorFinding, type ReconcileOutput, reconcile } from '../reconcile';
import { applyRedactions, type RedactionSpan, redactSecrets } from '../redact';
import { captureSnapshot } from '../snapshot';
import { AI_POLICY_VERSION, FINGERPRINT_ALGORITHM } from '../version';

export interface ScanDeps {
  repo: ScanRepository;
  artifacts: ArtifactStore;
  sandbox: SandboxRunner;
  source: SourceTree;
  scanners: ScannerAdapter[];
  logger: Logger;
  clock: Clock;
  /** Host directory under which scanner tasks get scratch directories. */
  workRoot: string;
  knowledgeBase?: KnowledgeBasePort;
  codeIntel?: CodeIntelPort;
  explainer?: FindingExplainer;
  investigator?: Investigator;
}

export type BaselineSelector =
  | { kind: 'auto' }
  | { kind: 'scan'; scanId: string }
  | { kind: 'branch'; branch: string }
  | { kind: 'none' };

export interface AiScanOptions {
  level: 'off' | 'explain' | 'standard';
  maxFindings: number;
  maxCostUsd: number;
}

export interface ScanRequest {
  projectName: string;
  mode: ScanMode;
  exclude: string[];
  baseline: BaselineSelector;
  /** Reuse scanner output from an earlier scan when all inputs are identical. */
  reuseCache: boolean;
  /** Restrict to these scanner ids. */
  scanners?: string[];
  /** Pin a knowledge base snapshot (default: latest). */
  kbSnapshotId?: string;
  /** INCREMENTAL: git ref the working tree is compared against. */
  diffBase?: string;
  /** TARGETED: files or directories to analyse. */
  paths?: string[];
  /** Branch the scan is attributed to; defaults to the git branch of the working tree. */
  branch?: string;
  ai?: AiScanOptions;
  resumeScanId?: string;
  signal?: AbortSignal;
  onProgress?: (event: ScanProgress) => void;
}

export interface ScanProgress {
  stage: 'snapshot' | 'manifest' | 'index' | 'impact' | 'scanner' | 'candidates' | 'ai' | 'reconcile' | 'done';
  message: string;
}

export interface ScanOutcome {
  scan: ScanRun;
  tasks: ScanTask[];
  assessments: FindingAssessment[];
  impact?: CodeImpactReport;
  ai?: { investigated: number; explained: number; skipped: number; costUsd: number; failures: string[] };
}

const EXCERPT_CONTEXT_LINES = 3;
const EXCERPT_MAX_LINES = 40;
const SCANNER_CONCURRENCY = 2;
/** Categories whose explanation needs other roles (dependency applicability) or would expose secrets. */
const NOT_EXPLAINED = new Set(['VULNERABLE_DEPENDENCY', 'HARDCODED_SECRET']);
const EXPLAINED_STATES = new Set(['NEW', 'REOPENED', 'NEEDS_RECONCILIATION']);

interface ScannerActivityInput {
  adapter: ScannerAdapter;
  identity: Record<string, unknown>;
  run: (taskId: string) => Promise<ScannerResult>;
}
type ScannerActivityOutput = Pick<ScannerResult, 'drafts' | 'rawArtifacts'>;

const scannerActivity: Activity<ScannerActivityInput, ScannerActivityOutput> = {
  name: 'scanner',
  kind: 'SCANNER',
  idempotencyKey: (input) => `scanner:${input.adapter.describe().id}:${digestOf(input.identity)}`,
  async run(input, ctx) {
    const result = await input.run(ctx.taskId);
    return {
      output: { drafts: result.drafts, rawArtifacts: result.rawArtifacts },
      coverage: result.coverage,
      status: result.coverage.completeness === 'COMPLETE' ? 'SUCCEEDED' : 'PARTIAL',
    };
  },
};

interface IndexOutput {
  artifactDigest: string;
  stats: Record<string, number>;
}
const indexActivity: Activity<{ identity: Record<string, unknown>; run: () => Promise<IndexOutput> }, IndexOutput> = {
  name: 'code-index',
  kind: 'INDEX',
  idempotencyKey: (input) => `index:${digestOf(input.identity)}`,
  run: async (input) => ({ output: await input.run() }),
};

const impactActivity: Activity<
  { identity: Record<string, unknown>; run: () => Promise<CodeImpactReport> },
  CodeImpactReport
> = {
  name: 'impact',
  kind: 'IMPACT',
  idempotencyKey: (input) => `impact:${digestOf(input.identity)}`,
  run: async (input) => ({ output: await input.run() }),
};

interface InvestigationOutput {
  drafts: CandidateDraft[];
  costUsd: number;
  deferred: string[];
  runIds: string[];
}
const investigationActivity: Activity<
  { identity: Record<string, unknown>; run: () => Promise<InvestigationOutput> },
  InvestigationOutput
> = {
  name: 'ai-investigation',
  kind: 'AGENT',
  idempotencyKey: (input) => `investigation:${digestOf(input.identity)}`,
  run: async (input) => ({ output: await input.run() }),
};

/** Scanners that run for a mode: dependency reassessment only re-runs SCA against new advisories. */
export function scannersForMode(
  scanners: readonly ScannerAdapter[],
  mode: ScanMode,
  only?: readonly string[],
): ScannerAdapter[] {
  return scanners.filter((s) => {
    const info = s.describe();
    if (only?.length && !only.includes(info.id)) return false;
    if (mode === 'DEPENDENCY_REASSESSMENT') return info.capabilities.includes('SCA');
    return true;
  });
}

/**
 * Scan use-case (docs/architecture/01 section 6): capture snapshot, freeze manifest, index code,
 * compute impact (incremental), run scanners, normalize candidates, investigate with AI, reconcile
 * against the baseline, explain new findings, and persist assessments. Every step is checkpointed so
 * `resumeScanId` continues an interrupted scan.
 */
export async function runScan(deps: ScanDeps, request: ScanRequest): Promise<ScanOutcome> {
  const { repo, artifacts, clock, logger } = deps;
  const progress = request.onProgress ?? (() => {});
  const { project, repository } = await repo.ensureProject({ name: request.projectName, rootPath: deps.source.root });
  const selected = scannersForMode(deps.scanners, request.mode, request.scanners);
  if (request.mode === 'INCREMENTAL' && !request.diffBase)
    throw new SpinxscaError('incremental scans need --diff <git ref>', 'INVALID');
  if (request.mode === 'TARGETED' && !request.paths?.length)
    throw new SpinxscaError('targeted scans need at least one path', 'INVALID');

  progress({ stage: 'snapshot', message: 'capturing source snapshot' });
  const { snapshot, files } = await captureSnapshot(
    { source: deps.source, artifacts, clock },
    { repositoryId: repository.repositoryId, exclude: request.exclude },
  );
  await repo.saveSnapshot(snapshot);

  let scan: ScanRun;
  if (request.resumeScanId) {
    const existing = await repo.getScan(request.resumeScanId);
    if (!existing) throw new SpinxscaError(`scan ${request.resumeScanId} not found`, 'NOT_FOUND');
    if (existing.manifest.source.contentManifestDigest !== snapshot.contentManifestDigest) {
      throw new SpinxscaError(
        `source changed since scan ${existing.scanId} started; start a new scan instead of resuming`,
        'SOURCE_CHANGED',
      );
    }
    if (existing.status === 'COMPLETED') {
      return {
        scan: existing,
        tasks: await repo.listTasks(existing.scanId),
        assessments: await repo.listAssessments(existing.scanId),
      };
    }
    scan = existing;
    await repo.updateScan(scan.scanId, { status: 'RUNNING' });
  } else {
    const scanId = newId('scan');
    const branch = request.branch ?? snapshot.branchAtCapture;
    const baseline = await resolveBaseline(repo, project.projectId, request.baseline, branch);
    progress({ stage: 'manifest', message: 'freezing analysis manifest' });
    const usesKb = selected.some((s) => s.describe().capabilities.includes('SCA'));
    const knowledgeBase =
      usesKb && deps.knowledgeBase ? await deps.knowledgeBase.resolveSnapshot(request.kbSnapshotId) : null;
    if (request.kbSnapshotId && !knowledgeBase)
      throw new SpinxscaError(`knowledge base snapshot ${request.kbSnapshotId} not found`, 'NOT_FOUND');
    const requestedAt = clock.now().toISOString();
    const aiRole =
      request.ai?.level === 'standard'
        ? (deps.investigator ?? deps.explainer)
        : request.ai?.level === 'explain'
          ? deps.explainer
          : undefined;
    const manifest = await buildManifest({
      scanId,
      snapshot,
      scanners: selected,
      mode: request.mode,
      exclude: request.exclude,
      baselineScanId: baseline?.scanId,
      requestedAt,
      knowledgeBase,
      ...(branch ? { branch } : {}),
      aiPolicy:
        request.ai && request.ai.level !== 'off' && aiRole
          ? {
              level: request.ai.level,
              policyVersion: aiRole.info.policyVersion,
              promptBundleDigest: aiRole.info.promptBundleDigest,
              provider: aiRole.info.provider,
              model: aiRole.info.model,
            }
          : { level: 'off', policyVersion: AI_POLICY_VERSION },
    });
    scan = {
      scanId,
      projectId: project.projectId,
      repositoryId: repository.repositoryId,
      snapshotId: snapshot.snapshotId,
      mode: request.mode,
      status: 'RUNNING',
      manifest,
      manifestDigest: digestOf(manifest),
      ...(baseline ? { baselineScanId: baseline.scanId } : {}),
      requestedAt,
      startedAt: requestedAt,
    };
    await repo.createScan(scan);
  }

  try {
    const outcome = await executeScan(deps, request, scan, selected, files, progress);
    progress({ stage: 'done', message: `scan ${outcome.scan.status.toLowerCase()}` });
    return outcome;
  } catch (err) {
    const status: ScanStatus = request.signal?.aborted ? 'CANCELLED' : 'FAILED';
    await repo.updateScan(scan.scanId, { status, error: errorMessage(err), completedAt: clock.now().toISOString() });
    logger.error(`scan ${scan.scanId} ${status.toLowerCase()}: ${errorMessage(err)}`);
    throw err;
  }
}

async function executeScan(
  deps: ScanDeps,
  request: ScanRequest,
  scan: ScanRun,
  selected: readonly ScannerAdapter[],
  files: SnapshotFile[],
  progress: (event: ScanProgress) => void,
): Promise<ScanOutcome> {
  const { repo, artifacts, clock, logger } = deps;
  const snapshot = await repo.getSnapshot(scan.snapshotId);
  if (!snapshot) throw new SpinxscaError(`snapshot ${scan.snapshotId} missing`, 'NOT_FOUND');
  const kb = scan.manifest.knowledgeBase;
  const kbRef: KnowledgeBaseRef | undefined = kb
    ? { snapshotId: kb.snapshotId, digest: kb.digest, ecosystems: kb.ecosystems }
    : undefined;
  const runnerDeps = {
    repo,
    artifacts,
    logger,
    clock,
    reuseAcrossScans: request.reuseCache,
    ...(request.signal ? { signal: request.signal } : {}),
  };
  const filePaths = new Set(files.map((f) => f.path));

  // 1. Code index (cached per file; reused across scans of the same snapshot).
  let graph: CodeGraphView | undefined;
  let indexDigest: string | undefined;
  // Dependency reassessment re-runs SCA only (new advisories); the code index is not needed.
  if (deps.codeIntel && scan.mode !== 'DEPENDENCY_REASSESSMENT') {
    progress({ stage: 'index', message: 'indexing code' });
    const codeIntel = deps.codeIntel;
    const result = await runActivity(runnerDeps, scan.scanId, indexActivity, {
      identity: {
        content: snapshot.contentManifestDigest,
        exclude: scan.manifest.scope.exclude,
        codeIntel: 'code-intel/v1',
      },
      run: async () => {
        const built = await codeIntel.build({
          snapshot,
          files,
          source: deps.source,
          artifacts,
          ...(request.signal ? { signal: request.signal } : {}),
        });
        graph = built.graph;
        return { artifactDigest: built.artifact.digest, stats: built.stats };
      },
    });
    if (result.output) {
      indexDigest = result.output.artifactDigest;
      graph ??= await codeIntel.load(artifacts, indexDigest as `sha256:${string}`);
    } else logger.warn('code index unavailable; continuing without symbol resolution');
  }

  // 2. Scope: incremental scans analyse the change impact, targeted scans the requested paths.
  let impact: CodeImpactReport | undefined;
  let scope: string[] | undefined;
  if (scan.mode === 'INCREMENTAL') {
    progress({ stage: 'impact', message: 'computing change impact' });
    const diffBase = request.diffBase as string;
    const changed = (await deps.source.changedFiles?.(diffBase))?.filter((p) => filePaths.has(p)) ?? [];
    const baselineScan = scan.baselineScanId ? await repo.getScan(scan.baselineScanId) : undefined;
    const baselineIndex = baselineScan
      ? (await repo.listTasks(baselineScan.scanId)).find((t) => t.kind === 'INDEX' && t.outputDigest)
      : undefined;
    const result = await runActivity(runnerDeps, scan.scanId, impactActivity, {
      identity: {
        content: snapshot.contentManifestDigest,
        diffBase,
        changed,
        baseline: baselineIndex?.outputDigest ?? null,
      },
      run: async () => {
        if (!deps.codeIntel || !graph) {
          return {
            changedFiles: changed,
            changedSymbols: [],
            affectedSymbols: {},
            affectedEndpoints: [],
            affectedControls: [],
            scope: changed,
            requiresExtendedScan: false,
          };
        }
        let base: CodeGraphView | undefined;
        if (baselineIndex?.outputDigest) {
          const output = JSON.parse(await artifacts.getText(baselineIndex.outputDigest)) as IndexOutput;
          if (await artifacts.has(output.artifactDigest as `sha256:${string}`))
            base = await deps.codeIntel.load(artifacts, output.artifactDigest as `sha256:${string}`);
        }
        return deps.codeIntel.impact(base, graph, changed);
      },
    });
    impact = result.output;
    scope = impact?.scope ?? changed;
  } else if (scan.mode === 'TARGETED') {
    const wanted = request.paths as string[];
    scope = files
      .map((f) => f.path)
      .filter((p) => wanted.some((w) => p === w || p.startsWith(`${w.replace(/\/+$/, '')}/`)));
  }

  // 3. Scanner tasks (checkpointed; reused on resume or when inputs are identical to an earlier scan).
  const applicable = selected.filter((s) => s.applies(files));
  const scannerOutputs: Array<{ task: ScanTask; output?: ScannerActivityOutput }> = [];
  const queue = [...applicable];
  const worker = async (): Promise<void> => {
    for (let adapter = queue.shift(); adapter; adapter = queue.shift()) {
      throwIfAborted(request.signal);
      const capability = adapter.describe();
      const scoped =
        scope && capability.scanModes.includes(scan.mode === 'TARGETED' ? 'TARGETED' : 'INCREMENTAL')
          ? scope
          : undefined;
      if (scoped && scoped.length === 0) {
        progress({ stage: 'scanner', message: `skipping ${capability.id} (nothing in scope)` });
        continue;
      }
      progress({
        stage: 'scanner',
        message: `running ${capability.id}${scoped ? ` on ${scoped.length} file(s)` : ''}`,
      });
      const ruleBundles = await adapter.ruleBundles();
      const usesKb = capability.capabilities.includes('SCA');
      const result = await runActivity(
        runnerDeps,
        scan.scanId,
        scannerActivity,
        {
          adapter,
          identity: {
            capability,
            ruleBundles,
            content: snapshot.contentManifestDigest,
            exclude: scan.manifest.scope.exclude,
            ...(scoped ? { scope: scoped } : {}),
            ...(usesKb ? { knowledgeBase: kb?.digest ?? null } : {}),
          },
          run: (taskId) =>
            adapter.run({
              scanId: scan.scanId,
              taskId,
              snapshot,
              source: deps.source,
              exclude: scan.manifest.scope.exclude,
              workDir: join(deps.workRoot, scan.scanId, taskId),
              sandbox: deps.sandbox,
              artifacts,
              logger,
              ...(request.signal ? { signal: request.signal } : {}),
              ...(usesKb && kbRef ? { knowledgeBase: kbRef } : {}),
              ...(scoped ? { scope: scoped } : {}),
            }),
        },
        { scannerId: capability.id },
      );
      scannerOutputs.push({ task: result.task, ...(result.output ? { output: result.output } : {}) });
    }
  };
  await Promise.all(Array.from({ length: Math.min(SCANNER_CONCURRENCY, queue.length) }, worker));
  throwIfAborted(request.signal);

  // 4. AI investigation (standard level): planner, investigators and baseline auditor produce drafts
  //    that are normalized like scanner output and reconciled with it (ADR-024).
  const aiStats = { investigated: 0, explained: 0, skipped: 0, costUsd: 0, failures: [] as string[] };
  let aiRan = false;
  const scannerDrafts = scannerOutputs.flatMap((o) => o.output?.drafts ?? []);
  const redactionsEarly = secretSpans(scannerDrafts);
  if (request.ai?.level === 'standard' && deps.investigator) {
    aiRan = true;
    const investigator = deps.investigator;
    const options = request.ai;
    progress({ stage: 'ai', message: 'planning and investigating' });
    const result = await runActivity(runnerDeps, scan.scanId, investigationActivity, {
      identity: { scanId: scan.scanId, policy: scan.manifest.aiPolicy, content: snapshot.contentManifestDigest },
      run: async () => {
        const outcome = await investigator.investigate(
          {
            scan,
            snapshotPaths: files.map((f) => f.path),
            ...(graph ? { graph } : {}),
            scannerCandidates: scannerDrafts.map((d) => ({
              category: d.category,
              title: d.title,
              locations: d.locations,
              ruleId: d.ruleId,
            })),
            ...(impact
              ? { focus: { files: impact.scope, endpointIds: impact.affectedEndpoints.map((e) => e.id) } }
              : {}),
            redactions: redactionsEarly,
          },
          deps.source,
          { maxCostUsd: options.maxCostUsd, ...(request.signal ? { signal: request.signal } : {}) },
        );
        for (const run of outcome.runs) await repo.saveAgentRun(run);
        return {
          drafts: outcome.drafts,
          costUsd: outcome.costUsd,
          deferred: outcome.deferred,
          runIds: outcome.runs.map((r) => r.agentRunId),
        };
      },
    });
    if (result.output) {
      aiStats.costUsd += result.output.costUsd;
      aiStats.investigated = result.output.drafts.length;
      if (result.output.deferred.length) aiStats.failures.push(`deferred: ${result.output.deferred.join('; ')}`);
      scannerOutputs.push({ task: result.task, output: { drafts: result.output.drafts, rawArtifacts: {} } });
    } else aiStats.failures.push(`investigation: ${result.task.error ?? result.task.status}`);
  }

  // 5. Candidates: the host assigns ids, fingerprints and evidence (ADR-022).
  let candidates = await repo.listCandidates(scan.scanId);
  if (candidates.length === 0) {
    progress({ stage: 'candidates', message: 'normalizing candidates' });
    const built = await buildCandidates(deps, scan, snapshot.snapshotId, scannerOutputs, graph);
    candidates = built.candidates;
    await repo.saveEvidence(built.evidence);
    await repo.saveCandidates(candidates);
  }
  const redactions = secretSpans(candidates);

  // 6. Reconciliation against the baseline (skipped on resume when already committed).
  let assessments = await repo.listAssessments(scan.scanId);
  if (assessments.length === 0) {
    progress({ stage: 'reconcile', message: 'reconciling with baseline' });
    const baselineScan = scan.baselineScanId ? await repo.getScan(scan.baselineScanId) : undefined;
    const baselineSnapshot = baselineScan ? await repo.getSnapshot(baselineScan.snapshotId) : undefined;
    const baselineFiles =
      baselineSnapshot && (await artifacts.has(baselineSnapshot.fileListDigest))
        ? new Map(
            (JSON.parse(await artifacts.getText(baselineSnapshot.fileListDigest)) as SnapshotFile[]).map((f) => [
              f.path,
              f.digest,
            ]),
          )
        : undefined;
    const prevKb = baselineScan?.manifest.knowledgeBase;
    const advisories =
      kb && prevKb && prevKb.snapshotId !== kb.snapshotId && deps.knowledgeBase
        ? await deps.knowledgeBase.diff(prevKb.snapshotId, kb.snapshotId)
        : kb && baselineScan && !prevKb && deps.knowledgeBase
          ? { added: new Set<string>(), modified: new Set<string>() }
          : undefined;
    const causesFor = buildCauseAttributor({
      ...(baselineScan ? { baseline: baselineScan.manifest } : {}),
      current: scan.manifest,
      ...(baselineFiles ? { baselineFiles } : {}),
      currentFiles: new Map(files.map((f) => [f.path, f.digest])),
      ...(advisories ? { advisories } : {}),
    });
    const prior = await loadPrior(repo, scan.projectId, baselineScan?.scanId);
    const coverage = buildCoverageOracle({
      snapshotPaths: filePaths,
      tasks: await taskCoverage(
        artifacts,
        scannerOutputs.map((s) => s.task).filter((t) => t.kind === 'SCANNER'),
      ),
    });
    const result = reconcile({
      projectId: scan.projectId,
      scanId: scan.scanId,
      snapshotId: scan.snapshotId,
      algorithm: FINGERPRINT_ALGORITHM,
      groups: groupCandidates(candidates),
      prior,
      fingerprintIndex: await repo.fingerprintIndex(scan.projectId),
      coverage,
      causesFor,
      nextSeq: await repo.nextFindingSeq(scan.projectId),
      now: clock.now().toISOString(),
      newId,
    });
    if (kb && deps.knowledgeBase?.intel) await attachIntel(deps.knowledgeBase, kb.snapshotId, result, candidates);
    if (request.ai && request.ai.level !== 'off' && deps.explainer) {
      const explained = await explainNewFindings(deps, request, scan, result, candidates, files, redactions, progress);
      aiStats.explained = explained.explained;
      aiStats.skipped = explained.skipped;
      aiStats.costUsd += explained.costUsd;
      aiStats.failures.push(...explained.failures);
      aiRan = true;
    }
    await repo.commitReconciliation(scan.scanId, result);
    assessments = result.assessments;
  }

  // 7. Summary and final status.
  const tasks = await repo.listTasks(scan.scanId);
  const scannerTasks = tasks.filter((t) => t.kind === 'SCANNER');
  const allOk = scannerTasks.length > 0 && scannerTasks.every((t) => t.status === 'SUCCEEDED');
  const anyOk = scannerTasks.some((t) => t.status === 'SUCCEEDED' || t.status === 'PARTIAL');
  const nothingToDo = scannerTasks.length === 0 && scope !== undefined && scope.length === 0;
  const status: ScanStatus = allOk || nothingToDo ? 'COMPLETED' : anyOk ? 'PARTIAL' : 'FAILED';
  const summary = summarize(
    candidates.length,
    assessments,
    allOk || nothingToDo ? 'COMPLETE' : anyOk ? 'PARTIAL' : 'FAILED',
  );
  const completedAt = clock.now().toISOString();
  const problems = [
    ...scannerTasks.filter((t) => t.error).map((t) => `${t.scannerId}: ${t.error}`),
    ...scannerTasks
      .filter((t) => t.status === 'PARTIAL')
      .map(
        (t) =>
          `${t.scannerId}: partial coverage${t.coverage?.toolErrors[0] ? ` (${t.coverage.toolErrors[0].message})` : ''}`,
      ),
  ];
  await repo.updateScan(scan.scanId, {
    status,
    summary,
    completedAt,
    ...(problems.length > 0 ? { error: problems.join('; ') } : {}),
  });
  const finalScan = (await repo.getScan(scan.scanId)) as ScanRun;
  if (status === 'FAILED') logger.error(`all scanner tasks failed for ${scan.scanId}`);
  return { scan: finalScan, tasks, assessments, ...(impact ? { impact } : {}), ...(aiRan ? { ai: aiStats } : {}) };
}

/**
 * Runs the explain role on new code findings before reconciliation is committed, so each finding
 * keeps a single assessment per scan (ADR-005). Completed runs are reused on resume; the scan-wide
 * cost budget stops further explanations once spent.
 */
async function explainNewFindings(
  deps: ScanDeps,
  request: ScanRequest,
  scan: ScanRun,
  result: ReconcileOutput,
  candidates: readonly FindingCandidate[],
  files: readonly SnapshotFile[],
  redactions: readonly Location[],
  progress: (event: ScanProgress) => void,
): Promise<{ explained: number; skipped: number; costUsd: number; failures: string[] }> {
  const explainer = deps.explainer as FindingExplainer;
  const options = request.ai as AiScanOptions;
  const candidateById = new Map(candidates.map((c) => [c.candidateId, c]));
  const occurrenceById = new Map(result.occurrences.map((o) => [o.occurrenceId, o]));
  const newFindings = new Map(result.newFindings.map((f) => [f.findingId, f]));
  const findingOf = async (id: string): Promise<Finding | undefined> => newFindings.get(id) ?? deps.repo.getFinding(id);
  const present = result.assessments.filter((a) => PRESENT_STATES.has(a.reconciliationState) && a.occurrenceId);
  const related = await Promise.all(
    present.map(async (a) => {
      const finding = await findingOf(a.findingId);
      const loc = occurrenceById.get(a.occurrenceId as string)?.locations[0];
      return {
        findingId: a.findingId,
        title: finding?.title ?? '',
        category: finding?.category ?? 'OTHER',
        location: loc ? `${loc.path}:${loc.startLine}` : '',
      };
    }),
  );
  const targets = [];
  for (const assessment of present) {
    if (!EXPLAINED_STATES.has(assessment.reconciliationState)) continue;
    const finding = await findingOf(assessment.findingId);
    if (!finding || NOT_EXPLAINED.has(finding.category)) continue;
    targets.push({ assessment, finding });
  }
  targets.sort(
    (a, b) =>
      SEVERITY_RANK[b.assessment.severity] - SEVERITY_RANK[a.assessment.severity] ||
      a.finding.findingId.localeCompare(b.finding.findingId),
  );

  const stats = { explained: 0, skipped: 0, costUsd: 0, failures: [] as string[] };
  const previousRuns = await deps.repo.listAgentRuns({ scanId: scan.scanId });
  const snapshotPaths = files.map((f) => f.path);
  for (const [index, target] of targets.entries()) {
    throwIfAborted(request.signal);
    if (index >= options.maxFindings || stats.costUsd >= options.maxCostUsd) {
      stats.skipped = targets.length - index;
      break;
    }
    const occurrence = occurrenceById.get(target.assessment.occurrenceId as string);
    if (!occurrence) continue;
    const reusable = previousRuns.find(
      (r) =>
        r.role === 'explain' &&
        r.findingId === target.finding.findingId &&
        r.subjectDigest === occurrence.fingerprint &&
        r.status === 'COMPLETED',
    );
    let run = reusable;
    let explanation = reusable?.output as ExplainOutput | undefined;
    if (!reusable) {
      progress({ stage: 'ai', message: `explaining ${target.finding.findingId} (${index + 1}/${targets.length})` });
      const subject: ExplainSubject = {
        scan,
        finding: target.finding,
        occurrence,
        candidates: occurrence.candidateIds
          .map((id) => candidateById.get(id))
          .filter((c): c is FindingCandidate => c !== undefined),
        evidence: await deps.repo.getEvidence(occurrence.evidenceIds),
        snapshotPaths,
        related: related.filter((r) => r.findingId !== target.finding.findingId),
        redactions,
      };
      try {
        const outcome = await explainer.explain(subject, deps.source, request.signal);
        run = outcome.run;
        explanation = outcome.explanation;
        await deps.repo.saveAgentRun(outcome.run);
      } catch (err) {
        stats.failures.push(`${target.finding.findingId}: ${errorMessage(err)}`);
        continue;
      }
    }
    stats.costUsd += run?.costUsd ?? 0;
    if (!explanation || run?.status !== 'COMPLETED') {
      stats.failures.push(
        `${target.finding.findingId}: ${run?.status ?? 'FAILED'}${run?.error ? ` (${run.error})` : ''}`,
      );
      continue;
    }
    const aiEvidence = await aiEvidenceRecords(deps, scan.snapshotId, explanation, redactions);
    await deps.repo.saveEvidence(aiEvidence);
    const merged: FindingAssessment = {
      ...target.assessment,
      classification: explanation.classification,
      severity: explanation.severity,
      confidence: explanation.confidence,
      exploitability: explanation.classification === 'UNLIKELY' ? 'UNLIKELY' : 'POTENTIAL',
      verificationLevel: 'L2_CONTEXT',
      attackPath: explanation.attackPath,
      evidenceIds: [...new Set([...target.assessment.evidenceIds, ...aiEvidence.map((e) => e.evidenceId)])],
      counterevidence: explanation.counterevidence,
      missingEvidence: explanation.missingEvidence,
      reasoningSummary: `${explanation.summary} Severity: ${explanation.severityRationale}`,
      assessedBy: `agent:explain/${run.model}`,
    };
    result.assessments[result.assessments.indexOf(target.assessment)] = merged;
    stats.explained++;
  }
  return stats;
}

type ExplainOutput = NonNullable<Awaited<ReturnType<FindingExplainer['explain']>>['explanation']>;

async function aiEvidenceRecords(
  deps: ScanDeps,
  snapshotId: string,
  explanation: ExplainOutput,
  redactions: readonly Location[],
): Promise<Evidence[]> {
  const out: Evidence[] = [];
  for (const item of explanation.evidence.slice(0, 6)) {
    const location: Location = { path: item.path, startLine: item.startLine, endLine: item.endLine, role: 'related' };
    const evidence = await snippetEvidence(
      (p) => deps.source.readText(p),
      snapshotId,
      'agent:explain',
      location,
      redactions,
      item.explanation,
    );
    if (evidence) out.push(evidence);
  }
  return out;
}

/** Adds KEV / EPSS / CVSS to dependency findings present in this scan (docs/architecture/04 section 5). */
async function attachIntel(
  kb: KnowledgeBasePort,
  snapshotId: string,
  result: ReconcileOutput,
  candidates: readonly FindingCandidate[],
): Promise<void> {
  const byId = new Map(candidates.map((c) => [c.candidateId, c]));
  const occurrences = new Map(result.occurrences.map((o) => [o.occurrenceId, o]));
  for (const [index, assessment] of result.assessments.entries()) {
    const occurrence = assessment.occurrenceId ? occurrences.get(assessment.occurrenceId) : undefined;
    if (!occurrence) continue;
    const ids = [...new Set(occurrence.candidateIds.flatMap((id) => byId.get(id)?.vulnerabilityIds ?? []))];
    if (ids.length === 0) continue;
    const intel = await kb.intel?.(snapshotId, ids);
    if (intel) result.assessments[index] = { ...assessment, intel };
  }
}

async function resolveBaseline(
  repo: ScanRepository,
  projectId: string,
  selector: BaselineSelector,
  branch: string | undefined,
): Promise<ScanRun | undefined> {
  if (selector.kind === 'none') return undefined;
  if (selector.kind === 'scan') {
    const scan = await repo.getScan(selector.scanId);
    if (!scan) throw new SpinxscaError(`baseline scan ${selector.scanId} not found`, 'NOT_FOUND');
    if (scan.projectId !== projectId)
      throw new SpinxscaError('baseline scan belongs to another project', 'INVALID_BASELINE');
    return scan;
  }
  const branchName = selector.kind === 'branch' ? selector.branch : branch;
  if (branchName) {
    const baseline = await repo.activeBaseline(projectId, 'BRANCH', branchName);
    if (baseline) return repo.getScan(baseline.scanId);
    if (selector.kind === 'branch') throw new SpinxscaError(`no baseline set for branch ${branchName}`, 'NOT_FOUND');
    // Without an explicit baseline, the previous scan of the same branch is the reference, so a fix
    // on one branch is not compared against another branch's state.
    const sameBranch = await latestScanOnBranch(repo, projectId, branchName);
    if (sameBranch) return sameBranch;
  }
  return repo.latestScan(projectId, ['COMPLETED', 'PARTIAL']);
}

async function loadPrior(
  repo: ScanRepository,
  projectId: string,
  baselineScanId: string | undefined,
): Promise<PriorFinding[]> {
  const findings = await repo.listFindings(projectId);
  if (findings.length === 0) return [];
  const baselineAssessments = baselineScanId ? await repo.listAssessments(baselineScanId) : [];
  const byFinding = new Map(baselineAssessments.map((a) => [a.findingId, a]));
  const latest = await repo.latestByFinding(projectId);
  return findings.map((finding) => {
    const l = latest.get(finding.findingId);
    const baselineAssessment = byFinding.get(finding.findingId);
    return {
      finding,
      ...(baselineAssessment ? { baselineAssessment } : {}),
      ...(l?.assessment ? { latestAssessment: l.assessment } : {}),
      ...(l?.occurrence ? { latestOccurrence: l.occurrence } : {}),
    };
  });
}

async function taskCoverage(artifacts: ArtifactStore, tasks: readonly ScanTask[]): Promise<TaskCoverage[]> {
  const result: TaskCoverage[] = [];
  for (const task of tasks) {
    const coverage: Coverage | undefined = task.coverage;
    let analyzedPaths = new Set<string>();
    if (coverage?.files.listDigest && (await artifacts.has(coverage.files.listDigest))) {
      analyzedPaths = new Set(JSON.parse(await artifacts.getText(coverage.files.listDigest)) as string[]);
    }
    result.push({
      scannerId: task.scannerId ?? task.name,
      succeeded: task.status === 'SUCCEEDED',
      coverage,
      analyzedPaths,
    });
  }
  return result;
}

/** Secret locations reported by secret scanners; masked in every stored excerpt and model input. */
export function secretSpans(candidates: readonly Pick<FindingCandidate, 'category' | 'locations'>[]): Location[] {
  return candidates.filter((c) => c.category === 'HARDCODED_SECRET').flatMap((c) => c.locations);
}

function overlaps(a: Location, b: Location): boolean {
  return a.path === b.path && a.startLine <= b.endLine && a.endLine >= b.startLine;
}

async function buildCandidates(
  deps: ScanDeps,
  scan: ScanRun,
  snapshotId: string,
  outputs: ReadonlyArray<{ task: ScanTask; output?: ScannerActivityOutput }>,
  graph: CodeGraphView | undefined,
): Promise<{ candidates: FindingCandidate[]; evidence: Evidence[] }> {
  const fileCache = new Map<string, string | undefined>();
  const readFile = async (path: string): Promise<string | undefined> => {
    if (!fileCache.has(path)) fileCache.set(path, await deps.source.readText(path));
    return fileCache.get(path);
  };

  type Pending = {
    draft: CandidateDraft;
    taskId: string;
    primary: Location;
    key: string;
    line: number;
    base: ReturnType<typeof anchorFor>;
  };
  const pending: Pending[] = [];
  for (const { task, output } of outputs) {
    for (const draft of output?.drafts ?? []) {
      const locations = draft.locations.map((l) => {
        const parsed = LocationSchema.parse(l);
        const symbol = graph?.symbolAt(parsed.path, parsed.startLine);
        return symbol && !parsed.symbolKey ? { ...parsed, symbolKey: symbol.key } : parsed;
      });
      const primary = locations.find((l) => l.role === 'primary') ?? locations[0];
      if (!primary) continue;
      const base = draft.anchorHint
        ? { path: primary.path, symbol: draft.anchorHint.symbol, shape: draft.anchorHint.shape }
        : anchorFor({
            path: primary.path,
            startLine: primary.startLine,
            endLine: primary.endLine,
            fileText: await readFile(primary.path),
          });
      const ruleFamily = draft.scanner === 'ai' ? familyOf(draft.category) : draft.ruleFamily;
      const key = [draft.category, ruleFamily, base.path, base.symbol, base.shape, draft.ruleId].join('|');
      pending.push({
        draft: { ...draft, ruleFamily, locations },
        taskId: task.taskId,
        primary,
        key,
        line: primary.startLine,
        base,
      });
    }
  }
  // Dedupe stage 1 (host): an AI finding overlapping a scanner finding of the same category takes the
  // scanner's anchor so both reconcile into one occurrence with the scanner candidate as primary.
  for (const item of pending) {
    if (item.draft.scanner !== 'ai') continue;
    const match = pending.find(
      (p) => p.draft.scanner !== 'ai' && p.draft.category === item.draft.category && overlaps(p.primary, item.primary),
    );
    if (match) {
      item.base = match.base;
      item.key = [
        item.draft.category,
        match.draft.ruleFamily,
        match.base.path,
        match.base.symbol,
        match.base.shape,
        item.draft.ruleId,
      ].join('|');
      item.draft = { ...item.draft, ruleFamily: match.draft.ruleFamily };
    }
  }
  const instances = assignInstances(pending);
  const redactions = secretSpans(pending.map((p) => p.draft));

  const evidenceById = new Map<string, Evidence>();
  const candidates: FindingCandidate[] = [];
  for (const item of pending) {
    const anchor = { ...item.base, instance: instances.get(item) ?? 0 };
    const fingerprint = semanticFingerprint({
      repositoryId: scan.repositoryId,
      category: item.draft.category,
      ruleFamily: item.draft.ruleFamily,
      anchor,
    });
    const evidenceIds: string[] = [];
    for (const location of item.draft.locations.filter((l) => l.role === 'primary' || l.role === 'source')) {
      const evidence = await snippetEvidence(readFile, snapshotId, item.draft.scanner, location, redactions);
      if (evidence) {
        evidenceById.set(evidence.evidenceId, evidence);
        evidenceIds.push(evidence.evidenceId);
      }
    }
    candidates.push({
      candidateId: `cand_${sha256Hex(`${scan.scanId}|${item.taskId}|${item.draft.ruleId}|${fingerprint}`).slice(0, 24)}`,
      scanId: scan.scanId,
      scanTaskId: item.taskId,
      scanner: item.draft.scanner,
      ruleId: item.draft.ruleId,
      ruleFamily: item.draft.ruleFamily,
      category: item.draft.category,
      cwe: item.draft.cwe,
      title: item.draft.title,
      message: redactSecrets(item.draft.message).text,
      severityHint: item.draft.severityHint,
      confidenceHint: item.draft.confidenceHint,
      locations: item.draft.locations,
      ...(item.draft.package ? { package: item.draft.package } : {}),
      ...(item.draft.vulnerabilityIds ? { vulnerabilityIds: item.draft.vulnerabilityIds } : {}),
      fingerprints: {
        ...(item.draft.scannerFingerprint ? { scanner: item.draft.scannerFingerprint } : {}),
        semantic: fingerprint,
        algorithm: FINGERPRINT_ALGORITHM,
        anchor,
      },
      evidenceIds,
    });
  }
  return { candidates, evidence: [...evidenceById.values()] };
}

async function snippetEvidence(
  readFile: (path: string) => Promise<string | undefined>,
  snapshotId: string,
  producer: string,
  location: Location,
  redactions: readonly RedactionSpan[],
  summary?: string,
): Promise<Evidence | undefined> {
  const text = await readFile(location.path);
  if (text === undefined) return undefined;
  const lines = text.split(/\r?\n/);
  if (location.startLine > lines.length) return undefined;
  const start = Math.max(1, location.startLine - EXCERPT_CONTEXT_LINES);
  const end = Math.min(lines.length, location.endLine + EXCERPT_CONTEXT_LINES, start + EXCERPT_MAX_LINES - 1);
  const masked = applyRedactions(lines.slice(start - 1, end), start, location.path, redactions);
  const numbered = masked.map((line, i) => `${String(start + i).padStart(5, ' ')} | ${line}`).join('\n');
  const excerpt = redactSecrets(numbered).text;
  return {
    evidenceId: `ev_${sha256Hex(`${snapshotId}|${location.path}|${start}|${end}|${excerpt}|${producer}`).slice(0, 24)}`,
    kind: 'CODE_SNIPPET',
    producedBy: producer,
    snapshotId,
    locations: [location],
    excerpt,
    summary: summary ?? `${location.role} at ${location.path}:${location.startLine}`,
  };
}

function summarize(
  candidateCount: number,
  assessments: readonly FindingAssessment[],
  completeness: ScanSummary['completeness'],
): ScanSummary {
  const bySeverity: Record<string, number> = {};
  const byState: Record<string, number> = {};
  let findings = 0;
  for (const a of assessments) {
    byState[a.reconciliationState] = (byState[a.reconciliationState] ?? 0) + 1;
    if (a.reconciliationState === 'RESOLVED') continue;
    findings++;
    bySeverity[a.severity] = (bySeverity[a.severity] ?? 0) + 1;
  }
  return {
    candidates: candidateCount,
    findings,
    bySeverity: bySeverity as ScanSummary['bySeverity'],
    byState: byState as ScanSummary['byState'],
    completeness,
  };
}
