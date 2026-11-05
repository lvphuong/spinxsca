import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { providerJudge } from '@spinxsca/agent';
import pc from 'picocolors';
import type { AiExplainOptions } from '../ai';
import { providerFor } from '../autonomy';
import { runAiSuite } from '../eval/ai-suite';
import { runGovernanceSuite } from '../eval/governance-runner';
import { locateSuite, runSuite, writeSuiteResults } from '../eval/harness';
import { createLogger, EXIT, status, table } from '../ui';

export interface EvalCommandOptions {
  suite: string;
  ai?: string;
  aiProvider?: string;
  casesDir?: string;
  case?: string[];
  out?: string;
  stability?: boolean;
  json?: boolean;
  verbose?: boolean;
}

export async function evalCommand(options: EvalCommandOptions): Promise<number> {
  if (options.suite === 'ai') return aiSuiteCommand(options);
  if (options.suite === 'governance') return governanceSuiteCommand(options);
  const suiteDir = resolve(locateSuite(options.suite, options.casesDir));
  const result = await runSuite({
    suiteDir,
    ...(options.case?.length ? { caseIds: options.case } : {}),
    stability: options.stability !== false,
    logger: createLogger(Boolean(options.verbose)),
    ...(options.ai && options.ai !== 'off'
      ? {
          aiLevel: options.ai as 'explain' | 'standard' | 'deep',
          ai: {
            provider: (options.aiProvider ?? 'scripted') as 'anthropic' | 'openai-compatible' | 'scripted',
            effort: 'high' as const,
            refusalFallback: 'default' as const,
            maxCostUsdPerFinding: 2,
          },
        }
      : {}),
    onProgress: (id, message) => {
      if (!options.json) status(`${id}: ${message}`);
    },
  });
  const outDir = resolve(
    options.out ?? join(suiteDir, '..', 'results', new Date().toISOString().replace(/[:.]/g, '-')),
  );
  mkdirSync(outDir, { recursive: true });
  writeSuiteResults(result, outDir);

  if (options.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return result.passed ? EXIT.OK : EXIT.POLICY_FAILED;
  }
  const rows = result.cases.map((c) => [
    c.id,
    c.error ? pc.red('error') : String(c.grade?.truePositives.length ?? 0),
    String(c.grade?.falsePositives.length ?? 0),
    String(c.grade?.falseNegatives.length ?? 0),
    String(c.grade?.pending.length ?? 0),
    c.stability ? `${c.stability.stable}/${c.stability.checked}` : '-',
    c.ai ? String(c.ai.explained) : '-',
    `${(c.durationMs / 1000).toFixed(1)}s`,
  ]);
  const lines = [
    '',
    table(['CASE', 'TP', 'FP', 'FN', 'PENDING', 'STABLE', 'AI', 'TIME'], rows),
    '',
    table(
      ['LAYER', 'TP', 'FP', 'FN', 'PRECISION', 'RECALL'],
      Object.entries(result.layers).map(([layer, m]) => [
        layer,
        String(m.truePositives),
        String(m.falsePositives),
        String(m.falseNegatives),
        m.precision.toFixed(3),
        m.recall.toFixed(3),
      ]),
    ),
    '',
    `precision ${result.precision.toFixed(3)} (min ${result.thresholds.precision_min})  recall ${result.recall.toFixed(3)} (min ${result.thresholds.recall_min})  identity ${result.identityStability === null ? 'n/a' : result.identityStability.toFixed(3)} (min ${result.thresholds.identity_stability_min})`,
  ];
  for (const c of result.cases) {
    for (const fp of c.grade?.falsePositives ?? [])
      lines.push(
        pc.yellow(
          `  FP ${c.id} ${fp.finding.findingId} ${fp.finding.category} ${fp.finding.path}:${fp.finding.startLine}${fp.negative ? ` (negative: ${fp.negative})` : ''}`,
        ),
      );
    for (const fn of c.grade?.falseNegatives ?? [])
      lines.push(pc.yellow(`  FN ${c.id} ${fn.id} ${fn.category} ${fn.path}:${fn.lines[0]}`));
    for (const p of c.stability?.problems ?? []) lines.push(pc.yellow(`  unstable ${c.id} ${p}`));
    if (c.error) lines.push(pc.red(`  error ${c.id}: ${c.error}`));
  }
  lines.push(
    '',
    result.passed ? pc.green('Evaluation passed.') : pc.red(`Evaluation failed: ${result.failures.join('; ')}`),
  );
  lines.push(pc.dim(`results: ${outDir}`));
  process.stdout.write(`${lines.join('\n')}\n`);
  return result.passed ? EXIT.OK : EXIT.POLICY_FAILED;
}

const aiFor = (provider: string | undefined, model?: string): AiExplainOptions => ({
  provider: (provider ?? 'scripted') as AiExplainOptions['provider'],
  ...(model ? { model } : {}),
  effort: 'high',
  refusalFallback: 'default',
  maxCostUsdPerFinding: 2,
});

/** `--suite ai`: deep, governed review on evals/ai; hard gates fail the run. */
async function aiSuiteCommand(options: EvalCommandOptions): Promise<number> {
  const suiteDir = resolve(locateSuite('ai', options.casesDir));
  const result = await runAiSuite({
    suiteDir,
    ...(options.case?.length ? { caseIds: options.case } : {}),
    ai: aiFor(options.aiProvider),
    logger: createLogger(Boolean(options.verbose)),
    onProgress: (id, message) => {
      if (!options.json) status(`${id}: ${message}`);
    },
  });
  const outDir = resolve(
    options.out ?? join(suiteDir, '..', 'results', `ai-${new Date().toISOString().replace(/[:.]/g, '-')}`),
  );
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, 'ai-suite.json'), `${JSON.stringify(result, null, 2)}\n`);
  if (options.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  else {
    console.log(
      table(
        ['Case', 'Status', 'False confirm', 'Leaks', 'Side effects', 'Checks', 'Cost', 'Time'],
        result.cases.map((c) => [
          c.id,
          c.error ? pc.red(`error: ${c.error.slice(0, 60)}`) : (c.caseStatus ?? '-'),
          String(c.falseConfirms.length),
          String(c.secretLeaks.length),
          String(c.sideEffects.length),
          `${c.checks.filter((k) => k.passed).length}/${c.checks.length}`,
          `$${c.costUsd.toFixed(2)}`,
          `${(c.durationMs / 1000).toFixed(1)}s`,
        ]),
      ),
    );
    status(
      `${result.passed ? pc.green('gates passed') : pc.red('gates failed')}: false confirmations ${result.gates.falseConfirms}, secret leaks ${result.gates.secretLeaks}, side effects ${result.gates.sideEffects}, errors ${result.gates.errors}; expected verdicts ${result.quality.passed}/${result.quality.total} (${result.provider})`,
    );
    for (const c of result.cases)
      for (const p of [...c.falseConfirms, ...c.secretLeaks, ...c.sideEffects]) status(`${c.id}: ${p}`);
    status(`results: ${outDir}`);
  }
  return result.passed ? EXIT.OK : EXIT.POLICY_FAILED;
}

/** `--suite governance`: decision matrix, plus the reviewer corpora with a real judge model. */
async function governanceSuiteCommand(options: EvalCommandOptions): Promise<number> {
  const suiteDir = resolve(locateSuite('governance', options.casesDir));
  const provider =
    options.aiProvider && options.aiProvider !== 'scripted' ? providerFor(aiFor(options.aiProvider)) : undefined;
  const result = await runGovernanceSuite({ suiteDir, ...(provider ? { judge: providerJudge(provider()) } : {}) });
  if (options.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  else {
    status(
      `decision matrix: ${result.matrix.passed}/${result.matrix.total} rows (${Object.entries(result.matrix.layers)
        .map(([l, n]) => `${l}:${n}`)
        .join(' ')})`,
    );
    for (const f of result.matrix.failures) status(pc.red(`${f.id}: expected ${f.expected}, got ${f.actual}`));
    if (result.reviewer) {
      status(
        `reviewer ${result.reviewer.judge}: ${result.reviewer.falseAllows.length} false allows on dangerous/injection, benign approved ${result.reviewer.benignApproved}/${result.reviewer.benign}, unsure ${result.reviewer.unsure}`,
      );
      for (const f of result.reviewer.falseAllows) status(pc.red(`false allow: ${f}`));
    } else status('reviewer corpora skipped (needs --ai-provider with a real model)');
  }
  return result.passed ? EXIT.OK : EXIT.POLICY_FAILED;
}
