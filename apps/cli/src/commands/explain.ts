import { askProject, explainFinding, SpinxscaError } from '@spinxsca/core';
import pc from 'picocolors';
import { loadConfig } from '../config';
import { type AiFlags, aiOptions, type CommonOptions, requireFinding, withEngine } from '../context';
import { CliError, EXIT, status } from '../ui';

export async function explainCommand(
  findingId: string,
  path: string | undefined,
  options: CommonOptions & AiFlags,
): Promise<number> {
  const ai = aiOptions(loadConfig(options.config), { ...options, ai: 'explain' }, true);
  if (!ai) throw new CliError('AI is not configured');
  return withEngine(path, { ...options, aiConfig: ai }, async (engine) => {
    if (!engine.explainer) throw new CliError('AI explainer unavailable');
    await requireFinding(engine, findingId, path);
    if (!options.json)
      status(
        `explaining ${findingId} with ${engine.explainer.info.provider}/${engine.explainer.info.model} (budget $${ai.maxCostUsd}); redacted code excerpts are sent to the provider`,
      );
    try {
      const outcome = await explainFinding(
        { repo: engine.repo, artifacts: engine.artifacts, source: engine.source, explainer: engine.explainer },
        findingId,
      );
      if (options.json) {
        process.stdout.write(`${JSON.stringify(outcome, null, 2)}\n`);
        return outcome.explanation ? EXIT.OK : EXIT.ERROR;
      }
      const run = outcome.run;
      const usage = `${run.usage.inputTokens + run.usage.cacheReadTokens} in / ${run.usage.outputTokens} out tokens${run.costUsd !== undefined ? `, $${run.costUsd.toFixed(4)}` : ''}`;
      if (!outcome.explanation) {
        process.stdout.write(
          `${pc.red(run.status.toLowerCase())}${run.error ? `: ${run.error}` : ''}${run.refusalCategory ? ` (refusal: ${run.refusalCategory})` : ''} · ${usage}\n`,
        );
        return EXIT.ERROR;
      }
      const e = outcome.explanation;
      const lines = [
        `${pc.bold(findingId)} ${e.classification.toLowerCase()} · ${e.severity} · confidence ${e.confidence.toLowerCase()} ${pc.dim(`(${run.modelsUsed.join(', ')}, ${usage})`)}`,
        '',
        e.summary,
        '',
        `${pc.dim('attacker')}  ${e.attackPath.attacker}`,
        `${pc.dim('entry')}     ${e.attackPath.entryPoint}`,
        `${pc.dim('source')}    ${e.attackPath.source}`,
        `${pc.dim('sink')}      ${e.attackPath.sink}`,
        ...e.attackPath.controls.map((c) => `${pc.dim('control')}   ${c}`),
        '',
        pc.bold('Evidence'),
        ...e.evidence.map((x) => `  ${x.path}:${x.startLine}-${x.endLine}  ${x.explanation}`),
        ...(e.counterevidence.length
          ? ['', pc.bold('Counterevidence'), ...e.counterevidence.map((c) => `  - ${c}`)]
          : []),
        ...(e.missingEvidence.length
          ? ['', pc.bold('Not established'), ...e.missingEvidence.map((c) => `  - ${c}`)]
          : []),
        '',
        `${pc.bold('Severity')} ${e.severityRationale}`,
        '',
        `${pc.bold('Remediation')} ${e.remediation.strategy}`,
        ...e.remediation.steps.map((s, i) => `  ${i + 1}. ${s}`),
        ...(e.remediation.example ? ['', e.remediation.example] : []),
      ];
      process.stdout.write(`${lines.join('\n')}\n`);
      return EXIT.OK;
    } catch (err) {
      if (err instanceof SpinxscaError) throw new CliError(err.message);
      throw err;
    }
  });
}

export async function askCommand(
  question: string,
  path: string | undefined,
  options: CommonOptions & AiFlags & { finding?: string },
): Promise<number> {
  const ai = aiOptions(loadConfig(options.config), { ...options, ai: 'explain' }, true);
  if (!ai) throw new CliError('AI is not configured');
  if (ai.provider === 'scripted')
    throw new CliError('`ask` needs a model; the scripted provider only supports explain');
  return withEngine(path, { ...options, aiConfig: ai }, async (engine) => {
    if (!engine.assistant) throw new CliError('AI assistant unavailable');
    try {
      const outcome = await askProject(
        { repo: engine.repo, artifacts: engine.artifacts, source: engine.source, assistant: engine.assistant },
        { question, ...(options.finding ? { findingId: options.finding } : {}) },
      );
      if (options.json) {
        process.stdout.write(`${JSON.stringify(outcome, null, 2)}\n`);
        return outcome.answer ? EXIT.OK : EXIT.ERROR;
      }
      if (!outcome.answer) {
        process.stdout.write(
          `${pc.red(outcome.run.status.toLowerCase())}${outcome.run.error ? `: ${outcome.run.error}` : ''}\n`,
        );
        return EXIT.ERROR;
      }
      const cites = outcome.answer.citations.map((c) => `  ${c.path}:${c.startLine}-${c.endLine}`);
      process.stdout.write(
        `${outcome.answer.answer}\n${cites.length ? `\n${pc.dim('Sources')}\n${cites.join('\n')}\n` : ''}`,
      );
      return EXIT.OK;
    } catch (err) {
      if (err instanceof SpinxscaError) throw new CliError(err.message);
      throw err;
    }
  });
}
