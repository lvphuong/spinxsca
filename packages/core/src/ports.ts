/**
 * Ports implemented by adapters (ADR-017). Core never imports an adapter; runtimes (CLI, server,
 * Temporal worker) wire concrete implementations into use-cases.
 */
import type {
  AgentRunRecord,
  AiExplanation,
  ArtifactRef,
  Confidence,
  Coverage,
  Digest,
  Disposition,
  Evidence,
  Finding,
  FindingAssessment,
  FindingCandidate,
  FindingMatchEvent,
  FindingOccurrence,
  Location,
  PackageRef,
  RuleBundleRef,
  ScannerCapability,
  ScanRun,
  ScanStatus,
  ScanTask,
  Severity,
  SnapshotFile,
  SourceSnapshot,
  VulnIntel,
} from '@spinxsca/schemas';

export interface Logger {
  debug(message: string, fields?: Record<string, unknown>): void;
  info(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
}

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };

export const silentLogger: Logger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
};

/** Content-addressed blob storage. */
export interface ArtifactStore {
  put(data: string | Uint8Array, mediaType: string): Promise<ArtifactRef>;
  get(digest: Digest): Promise<Uint8Array>;
  getText(digest: Digest): Promise<string>;
  has(digest: Digest): Promise<boolean>;
}

export interface GitInfo {
  commitSha: string;
  treeSha?: string;
  branch?: string;
  /** True when the scanned directory has uncommitted or untracked changes. */
  dirty: boolean;
}

/** Read access to the source tree being scanned. Reads must stay inside the root (ADR-023). */
export interface SourceTree {
  /** Absolute host path of the scan root. */
  readonly root: string;
  listFiles(options: { exclude: readonly string[] }): Promise<SnapshotFile[]>;
  readText(relPath: string): Promise<string | undefined>;
  gitInfo(): Promise<GitInfo | undefined>;
  /** Files changed between a git ref and the working tree (added, modified, renamed, deleted). */
  changedFiles?(baseRef: string): Promise<string[]>;
}

export interface Mount {
  hostPath: string;
  containerPath: string;
  readOnly: boolean;
}

/** Sandbox profiles are chosen by the host, never by a model (ADR-025). */
export type SandboxProfile = 'scan' | 'validation' | 'patch';

export interface ContainerRunSpec {
  name: string;
  image: string;
  args: string[];
  env: Record<string, string>;
  mounts: Mount[];
  workdir: string;
  profile: SandboxProfile;
  resources: { cpus: number; memoryMb: number; pidsLimit?: number; timeoutSec: number };
}

export interface ContainerRunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  durationMs: number;
}

export interface SandboxPreflight {
  ok: boolean;
  runtime: string;
  version?: string;
  checks: Array<{ name: string; ok: boolean; detail: string }>;
}

export interface SandboxRunner {
  preflight(image: string): Promise<SandboxPreflight>;
  run(spec: ContainerRunSpec, signal?: AbortSignal): Promise<ContainerRunResult>;
}

/** Scanner output before the host assigns ids, fingerprints and evidence. */
export interface CandidateDraft {
  scanner: string;
  ruleId: string;
  ruleFamily: string;
  category: FindingCandidate['category'];
  cwe: string[];
  title: string;
  message: string;
  severityHint: Severity;
  confidenceHint: Confidence;
  locations: Location[];
  package?: PackageRef;
  vulnerabilityIds?: string[];
  scannerFingerprint?: string;
  /**
   * Stable identity parts supplied by the adapter when the source-code heuristics do not apply
   * (dependency findings: purl + advisory; secrets: rule + secret hash; misconfigurations: check id).
   */
  anchorHint?: { symbol: string; shape: string };
}

/** Knowledge base snapshot frozen into the Analysis Manifest (ADR-007). */
export interface KnowledgeBaseRef {
  snapshotId: string;
  digest: Digest;
  /** Ecosystems whose advisories are fully mirrored in the snapshot. */
  ecosystems: string[];
}

export interface KnowledgeBasePort {
  /** Latest snapshot, or the one named by `snapshotId`; null when the knowledge base is empty. */
  resolveSnapshot(snapshotId?: string): Promise<KnowledgeBaseRef | null>;
  /** Advisory ids added or modified between two snapshots. */
  diff(
    fromSnapshotId: string,
    toSnapshotId: string,
  ): Promise<{ added: ReadonlySet<string>; modified: ReadonlySet<string> }>;
  /** KEV / EPSS / CVSS for the vulnerability ids of one finding, as of a snapshot. */
  intel?(snapshotId: string, vulnerabilityIds: readonly string[]): Promise<VulnIntel | undefined>;
}

export interface ScannerRunContext {
  scanId: string;
  taskId: string;
  snapshot: SourceSnapshot;
  source: SourceTree;
  exclude: readonly string[];
  /** Host directory the adapter may use for outputs; removed after the task. */
  workDir: string;
  sandbox: SandboxRunner;
  artifacts: ArtifactStore;
  logger: Logger;
  signal?: AbortSignal;
  /** Knowledge base snapshot for dependency scanners. */
  knowledgeBase?: KnowledgeBaseRef;
  /** Incremental/targeted scans: analyse only these repository-relative files (scanners that support it). */
  scope?: readonly string[];
}

export interface ScannerResult {
  drafts: CandidateDraft[];
  coverage: Coverage;
  /** Raw tool outputs (SARIF, native JSON, SBOM) kept for audit. */
  rawArtifacts: Record<string, ArtifactRef>;
}

export interface ExplainSubject {
  scan: ScanRun;
  finding: Finding;
  occurrence: FindingOccurrence;
  candidates: FindingCandidate[];
  evidence: Evidence[];
  /** Paths in the snapshot; the explainer may only cite these. */
  snapshotPaths: readonly string[];
  /** Other findings of the same scan, for context. */
  related: Array<{ findingId: string; title: string; category: string; location: string }>;
  /** Secret locations that must be masked in anything sent to a model. */
  redactions: readonly Location[];
}

export interface ExplainOutcome {
  explanation?: AiExplanation;
  run: AgentRunRecord;
}

/** AI validator-lite + risk assessor (docs/architecture/03). Implemented by @spinxsca/agent. */
export interface FindingExplainer {
  readonly info: { provider: string; model: string; promptBundleDigest: Digest; policyVersion: string };
  explain(subject: ExplainSubject, source: SourceTree, signal?: AbortSignal): Promise<ExplainOutcome>;
}

export interface BaselineRecord {
  baselineId: string;
  projectId: string;
  scopeType: 'BRANCH' | 'RELEASE';
  scopeRef: string;
  scanId: string;
  reason: string;
  activatedAt: string;
  deactivatedAt?: string;
}

export interface ScannerAdapter {
  describe(): ScannerCapability;
  /** Deterministic description of the rules this adapter will execute; frozen into the manifest. */
  ruleBundles(): Promise<RuleBundleRef[]>;
  /** False when the scanner does not apply to the snapshot (for example no supported files). */
  applies(files: readonly SnapshotFile[]): boolean;
  run(ctx: ScannerRunContext): Promise<ScannerResult>;
}

export interface ProjectRecord {
  projectId: string;
  name: string;
  createdAt: string;
}

export interface RepositoryRecord {
  repositoryId: string;
  projectId: string;
  rootPath: string;
  createdAt: string;
}

export interface ReconciliationCommit {
  newFindings: Finding[];
  /** Additional fingerprints for existing findings (rename/relocation aliases). */
  fingerprintAliases: Array<{ findingId: string; fingerprint: string; algorithm: string }>;
  occurrences: FindingOccurrence[];
  assessments: FindingAssessment[];
  matchEvents: FindingMatchEvent[];
}

/** System of record for scans and findings (SQLite in v1, PostgreSQL in v2; ADR-019). */
export interface ScanRepository {
  ensureProject(input: {
    name: string;
    rootPath: string;
  }): Promise<{ project: ProjectRecord; repository: RepositoryRecord }>;
  getProject(): Promise<{ project: ProjectRecord; repository: RepositoryRecord } | undefined>;

  saveSnapshot(snapshot: SourceSnapshot): Promise<void>;
  getSnapshot(snapshotId: string): Promise<SourceSnapshot | undefined>;

  createScan(scan: ScanRun): Promise<void>;
  updateScan(
    scanId: string,
    patch: Partial<Pick<ScanRun, 'status' | 'startedAt' | 'completedAt' | 'summary' | 'error'>>,
  ): Promise<void>;
  getScan(scanId: string): Promise<ScanRun | undefined>;
  listScans(projectId: string, limit?: number): Promise<ScanRun[]>;
  latestScan(projectId: string, statuses: readonly ScanStatus[], excludeScanId?: string): Promise<ScanRun | undefined>;

  upsertTask(task: ScanTask): Promise<void>;
  listTasks(scanId: string): Promise<ScanTask[]>;
  /** A previously succeeded task with the same idempotency key, from any scan (artifact reuse). */
  findReusableTask(idempotencyKey: string): Promise<ScanTask | undefined>;

  saveCandidates(candidates: FindingCandidate[]): Promise<void>;
  listCandidates(scanId: string): Promise<FindingCandidate[]>;
  saveEvidence(evidence: Evidence[]): Promise<void>;
  getEvidence(ids: readonly string[]): Promise<Evidence[]>;

  nextFindingSeq(projectId: string): Promise<number>;
  listFindings(projectId: string): Promise<Finding[]>;
  getFinding(findingId: string): Promise<Finding | undefined>;
  /** Map of every known fingerprint (canonical and aliases) to its finding id. */
  fingerprintIndex(projectId: string): Promise<Map<string, string>>;

  /** Atomically persists the outcome of reconciliation for one scan. */
  commitReconciliation(scanId: string, commit: ReconciliationCommit): Promise<void>;
  listOccurrences(scanId: string): Promise<FindingOccurrence[]>;
  occurrencesForFinding(findingId: string): Promise<FindingOccurrence[]>;
  listAssessments(scanId: string): Promise<FindingAssessment[]>;
  /** Latest assessment and occurrence per finding across all scans of the project. */
  latestByFinding(
    projectId: string,
  ): Promise<Map<string, { assessment?: FindingAssessment; occurrence?: FindingOccurrence }>>;
  assessmentsForFinding(findingId: string): Promise<FindingAssessment[]>;
  listMatchEvents(scanId: string): Promise<FindingMatchEvent[]>;

  saveDisposition(disposition: Disposition): Promise<void>;
  listDispositions(projectId: string): Promise<Disposition[]>;

  /** Activates a baseline for a scope, deactivating the previous one atomically (optimistic check). */
  activateBaseline(baseline: BaselineRecord, expectedCurrentId?: string): Promise<void>;
  activeBaseline(
    projectId: string,
    scopeType: BaselineRecord['scopeType'],
    scopeRef: string,
  ): Promise<BaselineRecord | undefined>;
  listBaselines(projectId: string): Promise<BaselineRecord[]>;

  saveAgentRun(run: AgentRunRecord): Promise<void>;
  listAgentRuns(filter: { scanId?: string; findingId?: string }): Promise<AgentRunRecord[]>;
}

/** Structural view of the code index (implemented by @spinxsca/code-intel). */
export interface CodeSymbol {
  key: string;
  path: string;
  name: string;
  qualifiedName: string;
  kind: 'function' | 'method' | 'class' | 'handler' | 'module';
  startLine: number;
  endLine: number;
  owner?: string;
  exported: boolean;
}

export interface CodeEndpoint {
  id: string;
  path: string;
  line: number;
  method: string;
  route: string;
  framework: string;
  handlers: string[];
  controls: Array<{ ref: string; name: string; kind: string; source: string; path: string; line: number }>;
}

export interface CodeAuthContext {
  endpoint: CodeEndpoint;
  handlers: CodeSymbol[];
  controls: Array<{
    ref: string;
    name: string;
    kind: string;
    source: string;
    path: string;
    line: number;
    symbol?: CodeSymbol;
  }>;
  hasAuthentication: boolean;
  hasAuthorization: boolean;
}

export interface CodeCallEdge {
  from: string;
  to: string;
  path: string;
  line: number;
  confidence: string;
}

export interface CodeGraphView {
  readonly symbolCount: number;
  getSymbol(key: string): CodeSymbol | undefined;
  symbolAt(path: string, line: number): CodeSymbol | undefined;
  search(query: { name?: string; path?: string; kind?: CodeSymbol['kind']; limit?: number }): CodeSymbol[];
  callers(key: string): CodeCallEdge[];
  callees(key: string): CodeCallEdge[];
  endpoints(filter?: { path?: string; method?: string; route?: string }): CodeEndpoint[];
  authContext(endpointId: string): CodeAuthContext | undefined;
}

export interface CodeImpactReport {
  changedFiles: string[];
  changedSymbols: string[];
  affectedSymbols: Record<string, number>;
  affectedEndpoints: Array<Pick<CodeEndpoint, 'id' | 'method' | 'route' | 'path' | 'line'>>;
  affectedControls: string[];
  scope: string[];
  requiresExtendedScan: boolean;
}

export interface CodeIntelPort {
  /** Builds (or rebuilds from the per-file cache) the index of a snapshot and stores it as an artifact. */
  build(input: {
    snapshot: SourceSnapshot;
    files: readonly SnapshotFile[];
    source: SourceTree;
    artifacts: ArtifactStore;
    signal?: AbortSignal;
  }): Promise<{ artifact: ArtifactRef; graph: CodeGraphView; stats: Record<string, number> }>;
  load(artifacts: ArtifactStore, digest: Digest): Promise<CodeGraphView>;
  impact(base: CodeGraphView | undefined, current: CodeGraphView, changedFiles: readonly string[]): CodeImpactReport;
}

/** What the investigation roles see (docs/architecture/03 section 3): code, index, scanner candidates. */
export interface InvestigationSubject {
  scan: ScanRun;
  snapshotPaths: readonly string[];
  graph?: CodeGraphView;
  /** Scanner candidates already found, so investigators extend rather than repeat them. */
  scannerCandidates: ReadonlyArray<Pick<CandidateDraft, 'category' | 'title' | 'locations' | 'ruleId'>>;
  /** Incremental scans: focus on these files and endpoints. */
  focus?: { files: readonly string[]; endpointIds: readonly string[] };
  redactions: readonly Location[];
}

export interface InvestigationOutcome {
  /** AI findings as candidate drafts (scanner "ai"); the host assigns ids and fingerprints. */
  drafts: CandidateDraft[];
  runs: AgentRunRecord[];
  costUsd: number;
  /** Packets or checks the roles could not finish within budget. */
  deferred: string[];
}

/** Planner + investigators + baseline auditor (implemented by @spinxsca/agent). */
export interface Investigator {
  readonly info: FindingExplainer['info'];
  investigate(
    subject: InvestigationSubject,
    source: SourceTree,
    options: { maxCostUsd: number; signal?: AbortSignal },
  ): Promise<InvestigationOutcome>;
}
