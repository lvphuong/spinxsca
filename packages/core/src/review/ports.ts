import type {
  AgentRunRecord,
  CaseStatus,
  CaseVerdict,
  Coverage,
  Digest,
  Location,
  PocOracle,
  PocResult,
  ReachabilityLevel,
  ScanRun,
  SnapshotFile,
  SourceSnapshot,
} from '@spinxsca/schemas';
import type { ActivityRunnerDeps } from '../activity';
import type { CaseRepository } from '../case/ports';
import type { CandidateDraft, CodeGraphView, SourceTree } from '../ports';
import type { SecretScrubber } from '../redact';

/** An analyzer run requested by an agent (ADR-043). Recorded as a PROBE task, never as coverage. */
export type ProbeRequest =
  | { kind: 'scanner'; scanner: string; paths?: readonly string[] }
  | {
      kind: 'semgrep_rule';
      yaml: string;
      /** Known finding the rule generalises; the rule must reproduce it (±2 lines). */
      seed?: { path: string; line: number };
      paths?: readonly string[];
    };

export interface ProbeResult {
  taskId: string;
  reused: boolean;
  drafts: CandidateDraft[];
  coverage?: Coverage;
  /** Validation problems or tool errors, shown to the agent. */
  problems: string[];
  reproducedSeed?: boolean;
}

export interface ProbePort {
  /** Scanner ids an agent may re-run on a subset of paths. */
  readonly scanners: readonly string[];
  run(request: ProbeRequest, signal?: AbortSignal): Promise<ProbeResult>;
}

export interface DependencyInfo {
  ecosystem: string;
  name: string;
  version: string;
  manifestPath: string;
  direct?: boolean;
  scope: 'runtime' | 'development' | 'test' | 'unknown';
  purl: string;
}

export interface DependencyUsageInfo {
  level: ReachabilityLevel;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  symbolSource: 'advisory' | 'model' | 'none';
  importSites: Array<{ path: string; line: number; specifier: string }>;
  callSites: Array<{ path: string; line: number; callee: string }>;
  entrypoints: Array<{ id: string; method: string; route: string; path: string; line: number }>;
  detail: string;
}

/** Lockfile inventory and import/call reachability of a package (deterministic, offline). */
export interface DependencyPort {
  inventory(): Promise<DependencyInfo[]>;
  reachability(input: {
    ecosystem: string;
    name: string;
    /** Vulnerable functions from the advisory or proposed by the model. */
    symbols?: readonly string[];
    symbolSource?: 'advisory' | 'model';
  }): Promise<DependencyUsageInfo>;
}

export interface AdvisoryInfo {
  id: string;
  aliases: string[];
  summary: string;
  severity?: string;
  packages: Array<{ ecosystem: string; name: string; fixed: string[] }>;
  /** Vulnerable symbols named by the advisory (OSV ecosystem_specific / database_specific). */
  symbols: string[];
  kev?: { dateAdded: string };
  epss?: { score: number; percentile: number };
  references: string[];
}

/** Read-only knowledge base lookups as of the scan's snapshot. */
export interface KbLookupPort {
  advisories(ids: readonly string[]): Promise<AdvisoryInfo[]>;
}

/** The agent's shell: one command in the `analysis` sandbox over the redacted copy. */
export interface AnalysisShellPort {
  exec(
    command: string,
    options?: { timeoutSec?: number; signal?: AbortSignal },
  ): Promise<{
    exitCode: number;
    stdout: string;
    stderr: string;
    timedOut: boolean;
    durationMs: number;
  }>;
}

/** Secret findings in the git history (redacted by the scanner; values never leave it). */
export interface HistorySecretsPort {
  scan(signal?: AbortSignal): Promise<{
    outcome: 'RAN' | 'DEGRADED' | 'NOT_RUN';
    reason?: string;
    secrets: Array<{ commit: string; path: string; line: number; ruleId: string; fingerprint: string }>;
  }>;
}

/** Ports of one review case, built by the runtime for the scan being reviewed. */
export interface ReviewPorts {
  cases: CaseRepository;
  probe?: ProbePort;
  dependencies?: DependencyPort;
  kb?: KbLookupPort;
  shell?: AnalysisShellPort;
  history?: HistorySecretsPort;
  /** Sandboxed PoC runs (L3); absent when the runtime cannot execute repository code. */
  validation?: ValidationPort;
  /** Pinned images, so the policy engine can check sandbox floors per tool. */
  images: {
    toolbox: string;
    scanners: Readonly<Record<string, string>>;
    /** Interpreter images of PoC runs (node, python3). */
    interpreters?: Readonly<Record<string, string>>;
  };
  /** Host scratch directory of the case (analysis copy, workspaces). */
  workDir: string;
}

export interface ReviewPortContext {
  scan: ScanRun;
  snapshot: SourceSnapshot;
  files: readonly SnapshotFile[];
  graph?: CodeGraphView;
  runner: ActivityRunnerDeps;
  redactions: readonly Location[];
  scrubber: SecretScrubber;
}

export interface ReviewSubject {
  scan: ScanRun;
  snapshotPaths: readonly string[];
  graph?: CodeGraphView;
  /** Deterministic scanner drafts of this scan; each gets a case handle. */
  scannerDrafts: readonly CandidateDraft[];
  redactions: readonly Location[];
  scrubber: SecretScrubber;
  ports: ReviewPorts;
}

export interface ReviewOutcome {
  caseId: string;
  status: CaseStatus;
  /** Findings the agents discovered that an independent validator confirmed. */
  drafts: CandidateDraft[];
  /** Case conclusions keyed by draft reference (scanner and agent drafts). */
  verdicts: Array<{ draftRef: string; verdict: CaseVerdict }>;
  costUsd: number;
  deferred: string[];
  runIds: string[];
}

/** Autonomous, governed review (ADR-044). Implemented by @spinxsca/agent. */
export interface AutonomousReviewer {
  readonly info: { provider: string; model: string; promptBundleDigest: Digest; policyVersion: string };
  /** Digest of personas, playbooks, policy and toolbox; frozen into the Analysis Manifest. */
  readonly policyDigest: Digest;
  review(
    subject: ReviewSubject,
    source: SourceTree,
    options: {
      maxCostUsd: number;
      signal?: AbortSignal;
      onRun?: (run: AgentRunRecord) => Promise<void>;
      /** Continue this case (CASE_RESUME) instead of the scan's own. */
      caseId?: string;
    },
  ): Promise<ReviewOutcome>;
}

/** Sandboxed proof-of-concept runs of a case (ADR-045). */
export interface ValidationPort {
  /** Opens (or reopens) the validation workspace of a handle: a redacted copy plus a harness directory. */
  open(handle: string): Promise<{ workspaceId: string; interpreters: string[] }>;
  workspaces(): string[];
  writeHarness(workspaceId: string, relPath: string, content: string): Promise<void>;
  /** Runs the harness twice (attack and control) and lets the host oracle decide. */
  run(input: {
    workspaceId: string;
    handle: string;
    command: readonly string[];
    oracle: PocOracle;
    signal?: AbortSignal;
  }): Promise<ValidationRunResult>;
  /** Latest run of a handle in a workspace (survives restarts). */
  lastRun(workspaceId: string, handle: string): Promise<ValidationRunResult | undefined>;
  harnessFiles(workspaceId: string): Promise<Record<string, string>>;
}

export interface ValidationRunResult {
  workspaceId: string;
  handle: string;
  oracle: PocOracle;
  command: string[];
  outcome: PocResult['outcome'];
  attackTriggered: boolean;
  controlTriggered: boolean;
  detail: string;
  harnessDigest: Digest;
  /** Scrubbed, truncated output of both runs. */
  attackLog: string;
  controlLog: string;
  lintProblems: string[];
  at: string;
}
