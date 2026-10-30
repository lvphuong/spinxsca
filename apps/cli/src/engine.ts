import { mkdirSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { CodeIntelService } from '@spinxsca/code-intel';
import {
  type ArtifactStore,
  buildReportModel,
  type FindingExplainer,
  type Investigator,
  type Logger,
  type ProjectAssistant,
  type Remediator,
  type ScanDeps,
  type ScannerAdapter,
  type ScanRepository,
  systemClock,
} from '@spinxsca/core';
import { LocalKnowledgeBase } from '@spinxsca/kb';
import {
  REPORT_FILENAMES,
  type ReportFormat,
  renderCsv,
  renderJson,
  renderMarkdown,
  renderPrComment,
  renderSarif,
} from '@spinxsca/reporting';
import { DockerSandboxRunner } from '@spinxsca/sandbox';
import { GitleaksAdapter, OsvScannerAdapter, SemgrepAdapter, TrivyAdapter } from '@spinxsca/scanners';
import { type Severity, SpinxscaConfig } from '@spinxsca/schemas';
import { FsArtifactStore, SqliteScanRepository } from '@spinxsca/storage';
import { LocalSourceTree } from '@spinxsca/workspace';
import { type AiExplainOptions, createAi } from './ai';
import { configRuleDirs, type LoadedConfig } from './config';
import { bundleSpecs, resolveRulesRoot } from './rules';
import { CliError } from './ui';

export interface EngineOptions {
  scanRoot: string;
  stateDir?: string;
  /** Defaults to an empty configuration (all scanners enabled). */
  config?: LoadedConfig;
  kbDir?: string;
  logger: Logger;
  ai?: AiExplainOptions;
  /** Remote workers: project state lives on the control plane (ADR-037). */
  repo?: ScanRepository;
  artifacts?: ArtifactStore;
}

export interface Engine {
  scanRoot: string;
  stateDir: string;
  projectName: string;
  repo: ScanRepository;
  artifacts: ArtifactStore;
  sandbox: DockerSandboxRunner;
  source: LocalSourceTree;
  scanners: ScannerAdapter[];
  osv?: OsvScannerAdapter;
  kb?: LocalKnowledgeBase;
  codeIntel: CodeIntelService;
  explainer?: FindingExplainer;
  assistant?: ProjectAssistant;
  investigator?: Investigator;
  remediator?: Remediator;
  logger: Logger;
  close(): void;
}

/** Knowledge base directory: flag, SPINXSCA_KB_DIR, config (relative to the file), then ~/.spinxsca/kb. */
export function resolveKbDir(config: LoadedConfig, flag?: string): string {
  if (flag) return resolve(flag);
  if (process.env.SPINXSCA_KB_DIR) return resolve(process.env.SPINXSCA_KB_DIR);
  const configured = config.config.knowledge_base?.dir;
  if (configured) return resolve(config.path ? dirname(config.path) : process.cwd(), configured);
  return join(homedir(), '.spinxsca', 'kb');
}

/** Wires the local runtime: SQLite state, artifacts, Docker sandbox, scanners, knowledge base and AI. */
export function openEngine(options: EngineOptions): Engine {
  const absolute = resolve(options.scanRoot);
  let scanRoot: string;
  try {
    scanRoot = realpathSync(absolute);
    if (!statSync(scanRoot).isDirectory()) throw new Error('not a directory');
  } catch {
    throw new CliError(`scan path is not a directory: ${absolute}`);
  }
  const stateDir = resolve(options.stateDir ?? join(scanRoot, '.spinxsca'));
  mkdirSync(join(stateDir, 'artifacts'), { recursive: true });
  mkdirSync(join(stateDir, 'tmp'), { recursive: true });
  const local = options.repo ? undefined : SqliteScanRepository.open(join(stateDir, 'state.db'));
  const repo: ScanRepository = options.repo ?? (local as SqliteScanRepository);
  const config: LoadedConfig = options.config ?? { config: SpinxscaConfig.parse({ version: 1 }) };
  const scannerConfig = config.config.scan?.scanners;
  const scanners: ScannerAdapter[] = [];
  if (scannerConfig?.semgrep?.enabled !== false) {
    scanners.push(new SemgrepAdapter({ bundles: bundleSpecs(resolveRulesRoot(), configRuleDirs(config)) }));
  }
  let kb: LocalKnowledgeBase | undefined;
  let osv: OsvScannerAdapter | undefined;
  if (scannerConfig?.osv?.enabled !== false) {
    kb = LocalKnowledgeBase.open(resolveKbDir(config, options.kbDir));
    osv = new OsvScannerAdapter({ database: kb });
    scanners.push(osv);
  }
  if (scannerConfig?.gitleaks?.enabled !== false) scanners.push(new GitleaksAdapter());
  if (scannerConfig?.trivy?.enabled !== false) {
    scanners.push(new TrivyAdapter({ minSeverity: (scannerConfig?.trivy?.min_severity ?? 'MEDIUM') as Severity }));
  }
  const ai = options.ai ? createAi(options.ai) : undefined;
  return {
    scanRoot,
    stateDir,
    projectName: basename(scanRoot),
    repo,
    artifacts: options.artifacts ?? new FsArtifactStore(join(stateDir, 'artifacts')),
    sandbox: new DockerSandboxRunner({ logger: options.logger }),
    source: new LocalSourceTree(scanRoot),
    scanners,
    ...(osv ? { osv } : {}),
    ...(kb ? { kb } : {}),
    codeIntel: new CodeIntelService(stateDir),
    ...(ai
      ? { explainer: ai.explainer, assistant: ai.assistant, investigator: ai.investigator, remediator: ai.remediator }
      : {}),
    logger: options.logger,
    close: () => {
      local?.close();
      kb?.close();
    },
  };
}

export function scanDeps(engine: Engine): ScanDeps {
  return {
    repo: engine.repo,
    artifacts: engine.artifacts,
    sandbox: engine.sandbox,
    source: engine.source,
    scanners: engine.scanners,
    logger: engine.logger,
    clock: systemClock,
    workRoot: join(engine.stateDir, 'tmp'),
    ...(engine.kb ? { knowledgeBase: engine.kb } : {}),
    codeIntel: engine.codeIntel,
    ...(engine.explainer ? { explainer: engine.explainer } : {}),
    ...(engine.investigator ? { investigator: engine.investigator } : {}),
  };
}

export type ExportFormat = ReportFormat | 'csv' | 'cyclonedx' | 'pr-comment';

/** Renders reports from the system of record into `outDir` and returns the written paths. */
export async function writeReports(
  engine: Engine,
  scanId: string,
  formats: readonly ReportFormat[],
  outDir?: string,
): Promise<Record<string, string>> {
  const model = await buildReportModel(engine.repo, scanId);
  const dir = resolve(outDir ?? join(engine.stateDir, 'reports', scanId));
  mkdirSync(dir, { recursive: true });
  const written: Record<string, string> = {};
  for (const format of formats) {
    const content =
      format === 'sarif' ? renderSarif(model) : format === 'md' ? renderMarkdown(model) : renderJson(model);
    const path = join(dir, REPORT_FILENAMES[format]);
    writeFileSync(path, content);
    written[format] = path;
  }
  return written;
}

/** One export in any supported format (`spinxsca export`). */
export async function renderExport(engine: Engine, scanId: string, format: ExportFormat): Promise<string> {
  if (format === 'cyclonedx') return sbomFor(engine, scanId);
  const model = await buildReportModel(engine.repo, scanId);
  if (format === 'sarif') return renderSarif(model);
  if (format === 'md') return renderMarkdown(model);
  if (format === 'csv') return renderCsv(model);
  if (format === 'pr-comment') return renderPrComment(model);
  return renderJson(model);
}

/** The CycloneDX SBOM produced by the dependency scanner for a scan. */
export async function sbomFor(engine: Engine, scanId: string): Promise<string> {
  const task = (await engine.repo.listTasks(scanId)).find((t) => t.scannerId === 'osv-scanner' && t.outputDigest);
  if (!task?.outputDigest) throw new CliError(`scan ${scanId} has no dependency inventory (osv-scanner did not run)`);
  const output = JSON.parse(await engine.artifacts.getText(task.outputDigest)) as {
    rawArtifacts?: { sbom?: { digest: `sha256:${string}` } };
  };
  const digest = output.rawArtifacts?.sbom?.digest;
  if (!digest) throw new CliError(`scan ${scanId} has no SBOM`);
  return engine.artifacts.getText(digest);
}
