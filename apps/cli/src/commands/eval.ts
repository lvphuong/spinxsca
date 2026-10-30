import { mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import pc from 'picocolors';
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
  const suiteDir = resolve(locateSuite(options.suite, options.casesDir));
  const result = await runSuite({
    suiteDir,
    ...(options.case?.length ? { caseIds: options.case } : {}),
    stability: options.stability !== false,
    logger: createLogger(Boolean(options.verbose)),
    ...(options.ai === 'explain'
      ? {
          ai: {
            provider: (options.aiProvider ?? 'scripted') as 'anthropic' | 'scripted',
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
