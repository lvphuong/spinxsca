import { estimateExplainCost } from '@spinxsca/agent';
import {
  activeDispositions,
  type BaselineSelector,
  buildReportModel,
  evaluatePolicy,
  runScan,
  SpinxscaError,
} from '@spinxsca/core';
import { REPORT_FORMATS, type ReportFormat } from '@spinxsca/reporting';
import type { ScanMode, Severity } from '@spinxsca/schemas';
import pc from 'picocolors';
import { loadConfig } from '../config';
import { type AiFlags, aiOptions, type CommonOptions, withEngine } from '../context';
import { scanDeps, writeReports } from '../engine';
import { CliError, EXIT, severityLabel, status, table } from '../ui';

export interface ScanCommandOptions extends CommonOptions, AiFlags {
  mode?: string;
  scanners?: string;
  kbSnapshot?: string;
  baseline?: string;
  exclude?: string[];
  format?: string;
  out?: string;
  failOn?: string;
  allFindings?: boolean;
  requireCompleteCoverage?: boolean;
  resume?: string;
  cache?: boolean;
  maxAiFindings?: string;
  diff?: string;
  paths?: string[];
}

const MODES: Record<string, ScanMode> = {
  full: 'FULL',
  incremental: 'INCREMENTAL',
  targeted: 'TARGETED',
  'dependency-reassessment': 'DEPENDENCY_REASSESSMENT',
};

export async function scanCommand(path: string | undefined, options: ScanCommandOptions): Promise<number> {
  const loaded = loadConfig(options.config);
  const config = loaded.config;
  const formats = parseFormats(options.format, config.output?.formats);
  const failOn = options.failOn ? parseSeverity(options.failOn) : config.policy?.fail_on_severity;
  const exclude = [...(config.scan?.exclude ?? []), ...(options.exclude ?? [])];
  const mode = options.mode
    ? MODES[options.mode]
    : options.diff
      ? 'INCREMENTAL'
      : options.paths?.length
        ? 'TARGETED'
        : 'FULL';
  if (!mode) throw new CliError(`unknown --mode "${options.mode}" (expected ${Object.keys(MODES).join(', ')})`);
  if (mode === 'INCREMENTAL' && !options.diff) throw new CliError('--mode incremental needs --diff <git ref>');
  if (mode === 'TARGETED' && !options.paths?.length) throw new CliError('--mode targeted needs --paths <path>');
  const ai = aiOptions(loaded, options);
  const maxAiFindings = options.maxAiFindings ? Number(options.maxAiFindings) : (ai?.maxFindings ?? 20);

  return withEngine(path, { ...options, ...(ai ? { aiConfig: ai } : {}) }, async (engine) => {
    if (ai && !options.json) {
      const model = engine.explainer?.info.model ?? '';
      const each = estimateExplainCost(model, 1);
      status(
        `AI explain on: ${engine.explainer?.info.provider}/${model}, up to ${maxAiFindings} new findings${each !== undefined ? ` (about $${each.toFixed(2)} each)` : ''}, budget $${ai.maxCostUsd}. Redacted code excerpts are sent to the provider.`,
      );
    }
    const controller = new AbortController();
    const onSignal = () => {
      status('cancelling scan…');
      controller.abort();
    };
    process.once('SIGINT', onSignal);
    try {
      const outcome = await runScan(scanDeps(engine), {
        projectName: config.project?.name ?? engine.projectName,
        mode,
        exclude,
        baseline: parseBaseline(options.baseline),
        reuseCache: options.cache !== false,
        ...(options.scanners ? { scanners: options.scanners.split(',').map((s) => s.trim()) } : {}),
        ...(options.kbSnapshot ? { kbSnapshotId: options.kbSnapshot } : {}),
        ...(options.diff ? { diffBase: options.diff } : {}),
        ...(options.paths?.length ? { paths: options.paths } : {}),
        ...(ai ? { ai: { level: ai.level, maxFindings: maxAiFindings, maxCostUsd: ai.maxCostUsd } } : {}),
        ...(options.resume ? { resumeScanId: options.resume } : {}),
        signal: controller.signal,
        onProgress: (event) => {
          if (!options.json) status(event.message);
        },
      });
      const reports = await writeReports(engine, outcome.scan.scanId, formats, options.out);
      const model = await buildReportModel(engine.repo, outcome.scan.scanId);
      const suppressed = new Set(
        activeDispositions(await engine.repo.listDispositions(outcome.scan.projectId), new Date()).keys(),
      );
      const policy = evaluatePolicy(outcome.assessments, {
        ...(failOn ? { failOnSeverity: failOn } : {}),
        newFindingsOnly: options.allFindings ? false : (config.policy?.new_findings_only ?? true),
        suppressed,
      });
      const complete = outcome.scan.summary?.completeness === 'COMPLETE';
      let exitCode: number = EXIT.OK;
      if (outcome.scan.status === 'FAILED') exitCode = EXIT.ERROR;
      else if (!policy.passed) exitCode = EXIT.POLICY_FAILED;
      else if (options.requireCompleteCoverage && !complete) exitCode = EXIT.PARTIAL_COVERAGE;

      if (options.json) {
        process.stdout.write(
          `${JSON.stringify(
            {
              scanId: outcome.scan.scanId,
              mode: outcome.scan.mode,
              status: outcome.scan.status,
              summary: outcome.scan.summary,
              baselineScanId: outcome.scan.baselineScanId ?? null,
              knowledgeBase: outcome.scan.manifest.knowledgeBase,
              impact: outcome.impact ?? null,
              findings: model.present.map((e) => ({
                findingId: e.finding.findingId,
                severity: e.assessment.severity,
                state: e.assessment.reconciliationState,
                classification: e.assessment.classification,
                verification: e.assessment.verificationLevel,
                category: e.finding.category,
                location: e.occurrence?.locations[0] ?? null,
                title: e.finding.title,
                causes: e.assessment.changeCauses,
              })),
              suppressed: model.suppressed.map((e) => e.finding.findingId),
              resolved: model.resolved.map((e) => e.finding.findingId),
              notReevaluated: model.notReevaluated.map((e) => e.finding.findingId),
              ai: outcome.ai ?? null,
              policy: {
                evaluated: policy.evaluated,
                passed: policy.passed,
                violations: policy.violations.map((v) => v.findingId),
              },
              reports,
              exitCode,
            },
            null,
            2,
          )}\n`,
        );
        return exitCode;
      }

      const out: string[] = [''];
      out.push(
        `${pc.bold('Scan')} ${outcome.scan.scanId}  ${statusColor(outcome.scan.status)}  ${outcome.scan.mode.toLowerCase()}  coverage ${outcome.scan.summary?.completeness ?? '?'}`,
      );
      out.push(`${pc.dim('Baseline')} ${outcome.scan.baselineScanId ?? 'none (first assessment)'}`);
      const kb = outcome.scan.manifest.knowledgeBase;
      if (kb) {
        out.push(
          `${pc.dim('Knowledge base')} ${kb.snapshotId}${kb.ecosystems.length ? ` (mirrored: ${kb.ecosystems.join(', ')})` : ''}`,
        );
      }
      if (outcome.impact) {
        const i = outcome.impact;
        out.push(
          `${pc.dim('Impact')} ${i.changedFiles.length} changed file(s), ${i.changedSymbols.length} changed symbol(s), ${Object.keys(i.affectedSymbols).length} affected caller(s), ${i.affectedEndpoints.length} affected endpoint(s)${i.affectedControls.length ? pc.yellow(`, security controls changed: ${i.affectedControls.join(', ')}`) : ''}; scanned ${i.scope.length} file(s)`,
        );
        for (const e of i.affectedEndpoints.slice(0, 10)) {
          out.push(`  ${pc.dim('endpoint')} ${e.method} ${e.route} (${e.path}:${e.line})`);
        }
      }
      out.push('');
      if (model.present.length === 0) out.push(pc.green('No findings reported by the executed scanners.'));
      else
        out.push(
          table(
            ['ID', 'SEVERITY', 'STATE', 'CATEGORY', 'LOCATION', 'WHY'],
            model.present.map((e) => {
              const loc = e.occurrence?.locations[0];
              return [
                e.finding.findingId,
                severityLabel(e.assessment.severity),
                `${e.assessment.reconciliationState.toLowerCase()}${e.assessment.verificationLevel === 'L2_CONTEXT' ? ` · ${e.assessment.classification.toLowerCase()}` : ''}`,
                e.finding.category,
                loc ? `${loc.path}:${loc.startLine}` : '-',
                e.assessment.changeCauses.join(',').toLowerCase().replace(/_/g, ' '),
              ];
            }),
          ),
        );
      if (model.suppressed.length)
        out.push('', `${pc.dim('Suppressed')}: ${model.suppressed.map((e) => e.finding.findingId).join(', ')}`);
      if (model.resolved.length)
        out.push('', `${pc.green('Resolved')}: ${model.resolved.map((e) => e.finding.findingId).join(', ')}`);
      if (model.notReevaluated.length)
        out.push(
          '',
          `${pc.yellow('Not re-evaluated')}: ${model.notReevaluated.map((e) => e.finding.findingId).join(', ')}`,
        );
      if (outcome.ai) {
        out.push(
          '',
          `${pc.dim('AI')} investigated ${outcome.ai.investigated} finding(s), explained ${outcome.ai.explained}, skipped ${outcome.ai.skipped}, cost $${outcome.ai.costUsd.toFixed(4)}${outcome.ai.failures.length ? pc.yellow(`; notes: ${outcome.ai.failures.join('; ')}`) : ''}`,
        );
      }
      out.push('', pc.dim('Reports:'));
      for (const [format, file] of Object.entries(reports)) out.push(`  ${format.padEnd(5)} ${file}`);
      if (policy.evaluated) {
        out.push(
          '',
          policy.passed
            ? pc.green(`Policy passed (fail on ${failOn}).`)
            : pc.red(`Policy failed: ${policy.violations.map((v) => v.findingId).join(', ')} at or above ${failOn}.`),
        );
      }
      if (outcome.scan.error) out.push('', pc.yellow(`Scanner notes: ${outcome.scan.error}`));
      process.stdout.write(`${out.join('\n')}\n`);
      return exitCode;
    } catch (err) {
      if (err instanceof SpinxscaError) throw new CliError(err.message);
      throw err;
    } finally {
      process.off('SIGINT', onSignal);
    }
  });
}

export function parseBaseline(value: string | undefined): BaselineSelector {
  if (!value) return { kind: 'auto' };
  if (value === 'none') return { kind: 'none' };
  if (value.startsWith('branch:')) return { kind: 'branch', branch: value.slice('branch:'.length) };
  return { kind: 'scan', scanId: value };
}

function parseFormats(flag: string | undefined, fromConfig: readonly string[] | undefined): ReportFormat[] {
  const values = flag ? flag.split(',').map((s) => s.trim()) : (fromConfig ?? [...REPORT_FORMATS]);
  for (const value of values) {
    if (!(REPORT_FORMATS as readonly string[]).includes(value)) {
      throw new CliError(`unknown report format "${value}" (expected ${REPORT_FORMATS.join(', ')})`);
    }
  }
  return values as ReportFormat[];
}

export function parseSeverity(value: string): Severity {
  const upper = value.toUpperCase();
  if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(upper)) {
    throw new CliError(`unknown severity "${value}" (expected critical, high, medium, low, info)`);
  }
  return upper as Severity;
}

function statusColor(value: string): string {
  return value === 'COMPLETED' ? pc.green(value) : value === 'PARTIAL' ? pc.yellow(value) : pc.red(value);
}
