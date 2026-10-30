import { compareScans, SpinxscaError, setBaseline, systemClock } from '@spinxsca/core';
import pc from 'picocolors';
import { type CommonOptions, withEngine } from '../context';
import { CliError, EXIT, severityLabel, table } from '../ui';

export async function compareCommand(
  fromId: string,
  toId: string,
  path: string | undefined,
  options: CommonOptions,
): Promise<number> {
  return withEngine(path, options, async (engine) => {
    try {
      const result = await compareScans(engine.repo, fromId, toId);
      if (options.json) {
        process.stdout.write(
          `${JSON.stringify({ ...result, from: result.from.scanId, to: result.to.scanId }, null, 2)}\n`,
        );
        return EXIT.OK;
      }
      const lines = [
        `${pc.bold('Compare')} ${fromId} -> ${toId}`,
        `${pc.dim('validity')}  ${result.validity.toLowerCase().replace(/_/g, ' ')}${result.inputChanges.length ? ` (${result.inputChanges.join(', ').toLowerCase().replace(/_/g, ' ')})` : ''}`,
        `${pc.dim('summary')}   introduced ${result.summary.introduced} · fixed ${result.summary.fixed} · persisting ${result.summary.persisting} · not re-evaluated ${result.summary['not-reevaluated']}`,
        '',
      ];
      if (result.entries.length) {
        lines.push(
          table(
            ['ID', 'SEVERITY', 'TRANSITION', 'CATEGORY', 'CAUSES'],
            result.entries.map((e) => [
              e.findingId,
              severityLabel(e.severity),
              e.transition,
              e.category,
              e.causes.join(',').toLowerCase().replace(/_/g, ' '),
            ]),
          ),
        );
      }
      process.stdout.write(`${lines.join('\n')}\n`);
      return EXIT.OK;
    } catch (err) {
      if (err instanceof SpinxscaError) throw new CliError(err.message);
      throw err;
    }
  });
}

export async function baselineSetCommand(
  path: string | undefined,
  options: CommonOptions & { branch: string; scan?: string; reason: string },
): Promise<number> {
  return withEngine(path, options, async (engine) => {
    const project = await engine.repo.getProject();
    if (!project) throw new CliError('no scans yet; run `spinxsca scan` first');
    const scanId = options.scan ?? (await engine.repo.latestScan(project.project.projectId, ['COMPLETED']))?.scanId;
    if (!scanId) throw new CliError('no completed scan to promote');
    try {
      const baseline = await setBaseline(engine.repo, systemClock, {
        branch: options.branch,
        scanId,
        reason: options.reason,
      });
      if (options.json) process.stdout.write(`${JSON.stringify(baseline, null, 2)}\n`);
      else process.stdout.write(`${pc.green('baseline')} ${options.branch} -> ${scanId} (${baseline.baselineId})\n`);
      return EXIT.OK;
    } catch (err) {
      if (err instanceof SpinxscaError || err instanceof Error) throw new CliError(err.message);
      throw err;
    }
  });
}

export async function baselineListCommand(path: string | undefined, options: CommonOptions): Promise<number> {
  return withEngine(path, options, async (engine) => {
    const project = await engine.repo.getProject();
    const baselines = project ? await engine.repo.listBaselines(project.project.projectId) : [];
    if (options.json) {
      process.stdout.write(`${JSON.stringify(baselines, null, 2)}\n`);
      return EXIT.OK;
    }
    if (baselines.length === 0) {
      process.stdout.write('No baselines. Set one with `spinxsca baseline set --branch main --reason "..."`.\n');
      return EXIT.OK;
    }
    process.stdout.write(
      `${table(
        ['SCOPE', 'SCAN', 'ACTIVE', 'ACTIVATED', 'REASON'],
        baselines.map((b) => [
          `${b.scopeType.toLowerCase()}:${b.scopeRef}`,
          b.scanId,
          b.deactivatedAt ? pc.dim('no') : pc.green('yes'),
          b.activatedAt,
          b.reason,
        ]),
      )}\n`,
    );
    return EXIT.OK;
  });
}
