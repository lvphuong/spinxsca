import {
  branchMatrix,
  DEFAULT_GATE_POLICY,
  evaluateReleaseGate,
  type ReleaseGatePolicy,
  systemClock,
} from '@spinxsca/core';
import type { SpinxscaConfig } from '@spinxsca/schemas';
import pc from 'picocolors';
import { type CommonOptions, withEngine } from '../context';
import type { Engine } from '../engine';
import { CliError, EXIT, severityLabel, table } from '../ui';
import { parseSeverity } from './scan';

export function gatePolicy(
  config: SpinxscaConfig,
  overrides: { maxScanAge?: string; failOn?: string } = {},
): ReleaseGatePolicy {
  const gate = config.gate;
  const policy: ReleaseGatePolicy = {
    maxScanAgeHours: gate?.max_scan_age_hours ?? DEFAULT_GATE_POLICY.maxScanAgeHours,
    failOnSeverity: gate?.fail_on_severity ?? DEFAULT_GATE_POLICY.failOnSeverity,
    blockKev: gate?.block_kev ?? DEFAULT_GATE_POLICY.blockKev,
    requireCompleteCoverage: gate?.require_complete_coverage ?? DEFAULT_GATE_POLICY.requireCompleteCoverage,
    ...(gate?.epss_threshold !== undefined ? { epssThreshold: gate.epss_threshold } : {}),
    ...(gate?.max_kb_age_hours !== undefined ? { maxKbAgeHours: gate.max_kb_age_hours } : {}),
  };
  if (overrides.maxScanAge) policy.maxScanAgeHours = parseHours(overrides.maxScanAge);
  if (overrides.failOn) policy.failOnSeverity = parseSeverity(overrides.failOn);
  return policy;
}

export function parseHours(value: string): number {
  const m = /^(\d+(?:\.\d+)?)\s*([hd]?)$/.exec(value.trim());
  if (!m) throw new CliError(`invalid duration "${value}" (examples: 72h, 3d)`);
  return Number(m[1]) * (m[2] === 'd' ? 24 : 1);
}

async function currentBranch(engine: Engine): Promise<string> {
  const git = await engine.source.gitInfo();
  if (!git?.branch) throw new CliError('cannot tell the branch of this directory; pass --branch <name>');
  return git.branch;
}

export async function gateCommand(
  path: string | undefined,
  options: CommonOptions & { branch?: string; maxScanAge?: string; failOn?: string },
): Promise<number> {
  return withEngine(path, options, async (engine, loaded) => {
    const project = await engine.repo.getProject();
    if (!project) throw new CliError('no scan recorded here; run `spinxsca scan` first');
    const branch = options.branch ?? (await currentBranch(engine));
    const result = await evaluateReleaseGate(engine.repo, {
      projectId: project.project.projectId,
      branch,
      policy: gatePolicy(loaded.config, options),
      now: systemClock.now(),
      kbSnapshotCreatedAt: async (id) => engine.kb?.store.snapshot(id)?.createdAt,
    });
    if (options.json) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      const lines = [
        `${pc.bold('Release gate')} ${branch}  ${result.passed ? pc.green('PASSED') : pc.red('FAILED')}${result.scan ? pc.dim(`  scan ${result.scan.scanId}`) : ''}`,
        '',
        ...result.checks.map((c) => `  ${c.passed ? pc.green('✓') : pc.red('✗')} ${c.message}`),
      ];
      if (result.blocking.length) {
        lines.push(
          '',
          table(
            ['ID', 'SEVERITY', 'WHY IT BLOCKS', 'TITLE'],
            result.blocking.map((b) => [b.findingId, severityLabel(b.severity), b.reasons.join('; '), b.title]),
          ),
        );
      }
      process.stdout.write(`${lines.join('\n')}\n`);
    }
    return result.passed ? EXIT.OK : EXIT.POLICY_FAILED;
  });
}

const STATE_LABEL = {
  OPEN: pc.red('open'),
  FIXED: pc.green('fixed'),
  NOT_REEVALUATED: pc.yellow('not re-evaluated'),
  SUPPRESSED: pc.dim('suppressed'),
} as const;

export async function branchesCommand(path: string | undefined, options: CommonOptions): Promise<number> {
  return withEngine(path, options, async (engine) => {
    const project = await engine.repo.getProject();
    if (!project) throw new CliError('no scan recorded here; run `spinxsca scan` first');
    const matrix = await branchMatrix(engine.repo, project.project.projectId, systemClock.now());
    if (options.json) {
      process.stdout.write(
        `${JSON.stringify(
          {
            branches: matrix.branches.map((b) => ({
              branch: b.branch,
              scanId: b.scan.scanId,
              completedAt: b.scan.completedAt,
              open: b.open,
              fixed: b.fixed,
            })),
            findings: matrix.rows.map((r) => ({
              findingId: r.finding.findingId,
              title: r.finding.title,
              branches: Object.fromEntries(
                Object.entries(r.cells).map(([b, c]) => [
                  b,
                  { state: c.state, severity: c.severity, scanId: c.scanId },
                ]),
              ),
            })),
          },
          null,
          2,
        )}\n`,
      );
      return EXIT.OK;
    }
    if (matrix.branches.length === 0) {
      process.stdout.write('No completed scans.\n');
      return EXIT.OK;
    }
    const names = matrix.branches.map((b) => b.branch);
    const lines = [
      table(
        ['BRANCH', 'LATEST SCAN', 'COMPLETED', 'OPEN', 'FIXED'],
        matrix.branches.map((b) => [
          b.branch,
          b.scan.scanId,
          b.scan.completedAt ?? '-',
          String(b.open),
          String(b.fixed),
        ]),
      ),
      '',
      table(
        ['ID', 'TITLE', ...names.map((n) => n.toUpperCase())],
        matrix.rows.map((r) => [
          r.finding.findingId,
          r.finding.title,
          ...names.map((n) => (r.cells[n] ? STATE_LABEL[r.cells[n].state] : pc.dim('-'))),
        ]),
      ),
    ];
    process.stdout.write(`${lines.join('\n')}\n`);
    return EXIT.OK;
  });
}
