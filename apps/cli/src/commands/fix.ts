import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { applyPatchToRepository, fixFinding, SpinxscaError, verifyFix } from '@spinxsca/core';
import { runProjectTests } from '@spinxsca/sandbox';
import pc from 'picocolors';
import { loadConfig } from '../config';
import { type AiFlags, aiOptions, type CommonOptions, requireFinding, withEngine } from '../context';
import { openEngine, scanDeps } from '../engine';
import { CliError, EXIT, status } from '../ui';

export async function fixCommand(
  findingId: string,
  path: string | undefined,
  options: CommonOptions & AiFlags & { apply?: boolean; patch?: string },
): Promise<number> {
  const loaded = loadConfig(options.config);
  const ai = aiOptions(loaded, { ...options, ai: 'explain' }, true);
  if (!ai) throw new CliError('AI is not configured');
  return withEngine(path, { ...options, aiConfig: ai }, async (engine) => {
    await requireFinding(engine, findingId, path);
    const patchesDir = join(engine.stateDir, 'patches');
    mkdirSync(patchesDir, { recursive: true });
    if (options.apply && options.patch) {
      const applied = applyPatchToRepository(engine.source, patchesDir, options.patch);
      process.stdout.write(`${pc.green('applied')} ${options.patch} to ${applied.files.join(', ')}\n`);
      return EXIT.OK;
    }
    if (!engine.remediator) throw new CliError('AI remediation unavailable');
    if (!options.json)
      status(
        `proposing a fix for ${findingId} with ${engine.remediator.info.provider}/${engine.remediator.info.model}; the patch is applied to a copy under .spinxsca/patches and verified by re-scan and tests`,
      );
    try {
      const result = await fixFinding(
        {
          scan: scanDeps(engine),
          remediator: engine.remediator,
          openWorkspace: async (stateDir) => {
            const engines: Array<ReturnType<typeof openEngine>> = [];
            return {
              deps: (sourceDir) => {
                const e = openEngine({
                  scanRoot: sourceDir,
                  stateDir,
                  config: loaded,
                  kbDir: join(stateDir, 'kb'),
                  logger: engine.logger,
                });
                engines.push(e);
                return scanDeps(e);
              },
              close: () => {
                for (const e of engines) e.close();
              },
            };
          },
          runTests: (workspace, signal) => runProjectTests(engine.sandbox, workspace, signal),
          patchesDir,
        },
        findingId,
      );
      if (options.json) {
        process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      } else {
        const color = result.status === 'verified' ? pc.green : result.status === 'rescan_passed' ? pc.yellow : pc.red;
        const lines = [`${pc.bold(result.patchId)} ${color(result.status)} — ${result.reason}`];
        if (result.proposal)
          lines.push('', result.proposal.summary, '', `${pc.dim('behaviour')} ${result.proposal.behaviourPreserved}`);
        lines.push(
          '',
          `${pc.dim('re-scan')} ${result.verification.rescan.toLowerCase()}${result.verification.newFindings.length ? ` (new findings: ${result.verification.newFindings.join(', ')})` : ''}`,
          `${pc.dim('tests')}   ${result.verification.tests.replace('_', ' ')}${result.verification.testOutput && result.verification.tests !== 'not_available' ? `: ${result.verification.testOutput.split('\n')[0]}` : ''}`,
        );
        if (result.diff) lines.push('', result.diff);
        if (result.status === 'verified' || result.status === 'rescan_passed') {
          lines.push(
            '',
            `${pc.dim('apply with')} spinxsca fix ${findingId} ${path ?? '.'} --apply --patch ${result.patchId}`,
          );
        }
        process.stdout.write(`${lines.join('\n')}\n`);
      }
      if (options.apply && (result.status === 'verified' || result.status === 'rescan_passed')) {
        const applied = applyPatchToRepository(engine.source, patchesDir, result.patchId);
        process.stdout.write(`${pc.green('applied')} to ${applied.files.join(', ')}\n`);
      }
      return result.status === 'verified' || result.status === 'rescan_passed' ? EXIT.OK : EXIT.POLICY_FAILED;
    } catch (err) {
      if (err instanceof SpinxscaError) throw new CliError(err.message);
      throw err;
    }
  });
}

export async function verifyFixCommand(
  findingId: string,
  path: string | undefined,
  options: CommonOptions,
): Promise<number> {
  return withEngine(path, options, async (engine) => {
    await requireFinding(engine, findingId, path);
    try {
      const result = await verifyFix(scanDeps(engine), findingId);
      if (options.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      else {
        const color = result.status === 'fixed' ? pc.green : result.status === 'still_vulnerable' ? pc.red : pc.yellow;
        process.stdout.write(
          `${findingId} ${color(result.status.replace('_', ' '))}: ${result.reason} ${pc.dim(`(scan ${result.scanId})`)}\n`,
        );
      }
      return result.status === 'fixed'
        ? EXIT.OK
        : result.status === 'still_vulnerable'
          ? EXIT.POLICY_FAILED
          : EXIT.PARTIAL_COVERAGE;
    } catch (err) {
      if (err instanceof SpinxscaError) throw new CliError(err.message);
      throw err;
    }
  });
}
