import {
  cpSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';
import { buildReportModel, type Logger, runScan, type ScanReportModel } from '@spinxsca/core';
import { importOsvFiles, KbStore } from '@spinxsca/kb';
import { type DetectionLayer, EvalCase, EvalThresholds } from '@spinxsca/schemas';
import { parse } from 'yaml';
import type { AiExplainOptions } from '../ai';
import { openEngine, scanDeps } from '../engine';
import { CliError } from '../ui';
import { type CaseGrade, findingLayer, gradeCase, type ReportedFinding, truthLayer } from './grader';

export interface SuiteOptions {
  suiteDir: string;
  caseIds?: string[];
  stability: boolean;
  logger: Logger;
  ai?: AiExplainOptions;
  onProgress?: (caseId: string, message: string) => void;
}

export interface StabilityResult {
  checked: number;
  stable: number;
  problems: string[];
}

export interface CaseResult {
  id: string;
  title: string;
  grade?: CaseGrade;
  findings: ReportedFinding[];
  stability?: StabilityResult;
  ai?: { explained: number; failures: string[]; costUsd: number };
  scanIds: string[];
  durationMs: number;
  error?: string;
}

export interface LayerMetrics {
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
}

export interface SuiteResult {
  suite: string;
  phase: number;
  thresholds: EvalThresholds;
  knowledgeBase?: { snapshotId: string; records: number };
  cases: CaseResult[];
  totals: { truePositives: number; falsePositives: number; falseNegatives: number; pending: number };
  layers: Partial<Record<DetectionLayer, LayerMetrics>>;
  precision: number;
  recall: number;
  identityStability: number | null;
  passed: boolean;
  failures: string[];
}

const SHIFT_LINES = 3;
const COMMENT_PREFIX: Record<string, string> = {
  js: '//',
  jsx: '//',
  mjs: '//',
  cjs: '//',
  ts: '//',
  tsx: '//',
  java: '//',
  py: '#',
};
/** Ecosystems the curated fixture knowledge base is declared complete for. */
const FIXTURE_ECOSYSTEMS = ['npm', 'PyPI', 'Maven'];

export function locateSuite(suite: string, explicit?: string): string {
  if (explicit) return explicit;
  let dir = process.cwd();
  for (;;) {
    const candidate = join(dir, 'evals', suite);
    if (existsSync(join(candidate, 'thresholds.yaml'))) return candidate;
    const parent = join(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }
  throw new CliError(
    `evaluation suite "${suite}" not found (looked for evals/${suite}/thresholds.yaml upwards from ${process.cwd()})`,
  );
}

export async function runSuite(options: SuiteOptions): Promise<SuiteResult> {
  const thresholds = EvalThresholds.parse(parse(readFileSync(join(options.suiteDir, 'thresholds.yaml'), 'utf8')));
  const caseDirs = readdirSync(options.suiteDir)
    .filter((name) => existsSync(join(options.suiteDir, name, 'case.yaml')))
    .filter((name) => !options.caseIds?.length || options.caseIds.includes(name))
    .sort();
  if (caseDirs.length === 0) throw new CliError(`no cases found in ${options.suiteDir}`);

  // Dependency cases are matched against a curated, pinned knowledge base, never the live OSV data.
  const kbDir = mkdtempSync(join(tmpdir(), 'spinxsca-eval-kb-'));
  let knowledgeBase: SuiteResult['knowledgeBase'];
  const fixtures = join(options.suiteDir, '..', 'fixtures', 'osv');
  if (existsSync(fixtures)) {
    const store = KbStore.open(kbDir);
    importOsvFiles(store, [fixtures], { sourceName: 'eval-fixtures', authoritativeFor: FIXTURE_ECOSYSTEMS });
    const snapshot = store.createSnapshot();
    knowledgeBase = { snapshotId: snapshot.snapshotId, records: snapshot.recordCount };
    store.close();
  }

  const cases: CaseResult[] = [];
  try {
    for (const name of caseDirs)
      cases.push(await runCase(join(options.suiteDir, name), thresholds.phase, kbDir, options));
  } finally {
    rmSync(kbDir, { recursive: true, force: true });
  }

  const totals = { truePositives: 0, falsePositives: 0, falseNegatives: 0, pending: 0 };
  const layerCounts = new Map<DetectionLayer, { tp: number; fp: number; fn: number }>();
  const bump = (layer: DetectionLayer, key: 'tp' | 'fp' | 'fn') => {
    const entry = layerCounts.get(layer) ?? { tp: 0, fp: 0, fn: 0 };
    entry[key]++;
    layerCounts.set(layer, entry);
  };
  let checked = 0;
  let stable = 0;
  for (const c of cases) {
    totals.truePositives += c.grade?.truePositives.length ?? 0;
    totals.falsePositives += c.grade?.falsePositives.length ?? 0;
    totals.falseNegatives += c.grade?.falseNegatives.length ?? 0;
    totals.pending += c.grade?.pending.length ?? 0;
    for (const tp of c.grade?.truePositives ?? []) bump(truthLayer(tp.truth), 'tp');
    for (const fn of c.grade?.falseNegatives ?? []) bump(truthLayer(fn), 'fn');
    for (const fp of c.grade?.falsePositives ?? []) bump(findingLayer(fp.finding), 'fp');
    checked += c.stability?.checked ?? 0;
    stable += c.stability?.stable ?? 0;
  }
  const ratio = (num: number, den: number) => (den === 0 ? 1 : num / den);
  const layers: SuiteResult['layers'] = {};
  for (const [layer, c] of [...layerCounts.entries()].sort()) {
    layers[layer] = {
      truePositives: c.tp,
      falsePositives: c.fp,
      falseNegatives: c.fn,
      precision: ratio(c.tp, c.tp + c.fp),
      recall: ratio(c.tp, c.tp + c.fn),
    };
  }
  const precision = ratio(totals.truePositives, totals.truePositives + totals.falsePositives);
  const recall = ratio(totals.truePositives, totals.truePositives + totals.falseNegatives);
  const identityStability = checked === 0 ? null : stable / checked;

  const failures: string[] = [];
  for (const c of cases) if (c.error) failures.push(`${c.id}: ${c.error}`);
  if (precision < thresholds.precision_min)
    failures.push(`precision ${precision.toFixed(3)} < ${thresholds.precision_min}`);
  if (recall < thresholds.recall_min) failures.push(`recall ${recall.toFixed(3)} < ${thresholds.recall_min}`);
  if (identityStability !== null && identityStability < thresholds.identity_stability_min) {
    failures.push(`identity stability ${identityStability.toFixed(3)} < ${thresholds.identity_stability_min}`);
  }
  return {
    suite: options.suiteDir,
    phase: thresholds.phase,
    thresholds,
    ...(knowledgeBase ? { knowledgeBase } : {}),
    cases,
    totals,
    layers,
    precision,
    recall,
    identityStability,
    passed: failures.length === 0,
    failures,
  };
}

async function runCase(caseDir: string, phase: number, kbDir: string, options: SuiteOptions): Promise<CaseResult> {
  const started = Date.now();
  const evalCase = EvalCase.parse(parse(readFileSync(join(caseDir, 'case.yaml'), 'utf8')));
  const progress = (message: string) => options.onProgress?.(evalCase.id, message);
  const work = mkdtempSync(join(tmpdir(), 'spinxsca-eval-'));
  const result: CaseResult = { id: evalCase.id, title: evalCase.title, findings: [], scanIds: [], durationMs: 0 };
  try {
    const sourceDir = join(work, 'src');
    cpSync(join(caseDir, evalCase.source), sourceDir, {
      recursive: true,
      filter: (path) => !path.split(sep).includes('.spinxsca') && !path.endsWith('case.yaml'),
    });
    const engine = openEngine({
      scanRoot: sourceDir,
      stateDir: join(work, 'state'),
      kbDir,
      logger: options.logger,
      ...(options.ai ? { ai: options.ai } : {}),
    });
    try {
      const deps = scanDeps(engine);
      const scan = async (label: string, baseline: 'none' | 'auto', withAi = false) => {
        progress(label);
        const outcome = await runScan(deps, {
          projectName: evalCase.id,
          mode: 'FULL',
          exclude: [],
          baseline: baseline === 'none' ? { kind: 'none' } : { kind: 'auto' },
          reuseCache: false,
          ...(withAi && options.ai
            ? { ai: { level: 'explain', maxFindings: 10, maxCostUsd: options.ai.maxCostUsdPerFinding } }
            : {}),
        });
        result.scanIds.push(outcome.scan.scanId);
        if (outcome.scan.status === 'FAILED') throw new Error(`scan failed: ${outcome.scan.error ?? 'unknown error'}`);
        if (outcome.ai)
          result.ai = { explained: outcome.ai.explained, failures: outcome.ai.failures, costUsd: outcome.ai.costUsd };
        return buildReportModel(engine.repo, outcome.scan.scanId);
      };

      const first = await scan('scan', 'none', true);
      result.findings = reported(first);
      result.grade = gradeCase(evalCase, result.findings, phase);

      if (options.stability && result.findings.length > 0) {
        const stability: StabilityResult = { checked: 0, stable: 0, problems: [] };
        const expectStable = (model: ScanReportModel, label: string) => {
          const states = new Map(model.present.map((e) => [e.finding.findingId, e.assessment.reconciliationState]));
          for (const f of result.findings) {
            stability.checked++;
            const state = states.get(f.findingId);
            if (state === 'EXISTING') stability.stable++;
            else stability.problems.push(`${label}: ${f.findingId} became ${state ?? 'absent'}`);
          }
          for (const e of model.present) {
            if (e.assessment.reconciliationState === 'NEW')
              stability.problems.push(`${label}: unexpected new ${e.finding.findingId}`);
          }
        };
        expectStable(await scan('rescan unchanged source', 'auto'), 'rescan');
        shiftSources(sourceDir);
        expectStable(await scan('rescan with shifted lines', 'auto'), 'shifted');
        if (renameSources(sourceDir) > 0) expectStable(await scan('rescan with renamed files', 'auto'), 'renamed');
        result.stability = stability;
      }
    } finally {
      engine.close();
    }
  } catch (err) {
    result.error = err instanceof Error ? err.message : String(err);
  } finally {
    rmSync(work, { recursive: true, force: true });
    result.durationMs = Date.now() - started;
  }
  return result;
}

function reported(model: ScanReportModel): ReportedFinding[] {
  return model.present.map((e) => {
    const loc = e.occurrence?.locations[0];
    const vulnerabilityIds = [...new Set(e.candidates.flatMap((c) => c.vulnerabilityIds ?? []))];
    return {
      findingId: e.finding.findingId,
      category: e.finding.category,
      cwe: e.finding.cwe,
      path: loc?.path ?? '',
      startLine: loc?.startLine ?? 0,
      endLine: loc?.endLine ?? 0,
      ...(vulnerabilityIds.length ? { vulnerabilityIds } : {}),
    };
  });
}

function codeFiles(root: string): string[] {
  const out: string[] = [];
  const visit = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) visit(path);
      else if (COMMENT_PREFIX[name.slice(name.lastIndexOf('.') + 1).toLowerCase()]) out.push(path);
    }
  };
  visit(root);
  return out;
}

/** Inserts comment lines at the top of every source file: findings must keep their identity. */
function shiftSources(root: string): void {
  for (const path of codeFiles(root)) {
    const prefix = COMMENT_PREFIX[path.slice(path.lastIndexOf('.') + 1).toLowerCase()] as string;
    const header = Array.from({ length: SHIFT_LINES }, (_, i) => `${prefix} spinxsca-eval shifted line ${i + 1}`).join(
      '\n',
    );
    writeFileSync(path, `${header}\n${readFileSync(path, 'utf8')}`);
  }
}

/** Renames every source file (a.js -> a_moved.js): findings must keep their identity through relocation. */
function renameSources(root: string): number {
  const files = codeFiles(root);
  for (const path of files) {
    const dot = path.lastIndexOf('.');
    renameSync(path, `${path.slice(0, dot)}_moved${path.slice(dot)}`);
  }
  return files.length;
}

export function writeSuiteResults(result: SuiteResult, outDir: string): void {
  const rel = (p: string) => relative(process.cwd(), p) || '.';
  writeFileSync(join(outDir, 'results.json'), `${JSON.stringify({ ...result, suite: rel(result.suite) }, null, 2)}\n`);
  const lines = [
    `# Evaluation results: ${rel(result.suite)}`,
    '',
    `Phase ${result.phase} · ${result.passed ? 'PASSED' : 'FAILED'}${result.knowledgeBase ? ` · knowledge base ${result.knowledgeBase.snapshotId} (${result.knowledgeBase.records} fixture advisories)` : ''}`,
    '',
    '| Metric | Value | Threshold |',
    '|---|---:|---:|',
    `| Precision | ${result.precision.toFixed(3)} | ${result.thresholds.precision_min} |`,
    `| Recall | ${result.recall.toFixed(3)} | ${result.thresholds.recall_min} |`,
    `| Identity stability | ${result.identityStability === null ? 'n/a' : result.identityStability.toFixed(3)} | ${result.thresholds.identity_stability_min} |`,
    '',
    '| Layer | TP | FP | FN | Precision | Recall |',
    '|---|---:|---:|---:|---:|---:|',
    ...Object.entries(result.layers).map(
      ([layer, m]) =>
        `| ${layer} | ${m.truePositives} | ${m.falsePositives} | ${m.falseNegatives} | ${m.precision.toFixed(3)} | ${m.recall.toFixed(3)} |`,
    ),
    '',
    '| Case | TP | FP | FN | Pending | Stable | AI | Time |',
    '|---|---:|---:|---:|---:|---:|---:|---:|',
    ...result.cases.map(
      (c) =>
        `| ${c.id}${c.error ? ' (error)' : ''} | ${c.grade?.truePositives.length ?? '-'} | ${c.grade?.falsePositives.length ?? '-'} | ${c.grade?.falseNegatives.length ?? '-'} | ${c.grade?.pending.length ?? '-'} | ${c.stability ? `${c.stability.stable}/${c.stability.checked}` : '-'} | ${c.ai ? c.ai.explained : '-'} | ${(c.durationMs / 1000).toFixed(1)}s |`,
    ),
    '',
  ];
  if (result.failures.length) lines.push('## Failures', '', ...result.failures.map((f) => `- ${f}`), '');
  writeFileSync(join(outDir, 'report.md'), lines.join('\n'));
}
