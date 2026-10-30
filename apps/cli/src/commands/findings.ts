import { activeDispositions, buildReportModel, disposeFinding, SpinxscaError, systemClock } from '@spinxsca/core';
import type { AiExplanation, Disposition } from '@spinxsca/schemas';
import pc from 'picocolors';
import { type CommonOptions, currentUser, requireFinding, withEngine } from '../context';
import { CliError, EXIT, severityLabel, table } from '../ui';

export async function findingsListCommand(
  path: string | undefined,
  options: CommonOptions & { scan?: string; state?: string },
): Promise<number> {
  return withEngine(path, options, async (engine) => {
    const project = await engine.repo.getProject();
    if (!project) throw new CliError('no scans yet; run `spinxsca scan` first');
    const scanId =
      options.scan ?? (await engine.repo.latestScan(project.project.projectId, ['COMPLETED', 'PARTIAL']))?.scanId;
    if (!scanId) throw new CliError('no completed scan found');
    const model = await buildReportModel(engine.repo, scanId);
    let entries = [...model.present, ...model.suppressed, ...model.notReevaluated, ...model.resolved];
    if (options.state) {
      const wanted = options.state.toUpperCase().replace(/-/g, '_');
      entries =
        wanted === 'SUPPRESSED'
          ? entries.filter((e) => e.disposition)
          : entries.filter((e) => e.assessment.reconciliationState === wanted && !e.disposition);
    }
    if (options.json) {
      process.stdout.write(
        `${JSON.stringify(
          entries.map((e) => ({
            finding: e.finding,
            assessment: e.assessment,
            location: e.occurrence?.locations[0] ?? null,
            disposition: e.disposition ?? null,
          })),
          null,
          2,
        )}\n`,
      );
      return EXIT.OK;
    }
    process.stdout.write(`${pc.dim(`scan ${scanId}`)}\n`);
    if (entries.length === 0) {
      process.stdout.write('No findings.\n');
      return EXIT.OK;
    }
    process.stdout.write(
      `${table(
        ['ID', 'SEVERITY', 'STATE', 'CATEGORY', 'LOCATION', 'TITLE'],
        entries.map((e) => {
          const loc = e.occurrence?.locations[0];
          return [
            e.finding.findingId,
            severityLabel(e.assessment.severity),
            e.disposition ? pc.dim(e.disposition.kind.toLowerCase()) : e.assessment.reconciliationState.toLowerCase(),
            e.finding.category,
            loc ? `${loc.path}:${loc.startLine}` : '-',
            e.finding.title.length > 70 ? `${e.finding.title.slice(0, 67)}...` : e.finding.title,
          ];
        }),
      )}\n`,
    );
    return EXIT.OK;
  });
}

export async function findingsShowCommand(
  findingId: string,
  path: string | undefined,
  options: CommonOptions,
): Promise<number> {
  return withEngine(path, options, async (engine) => {
    await requireFinding(engine, findingId, path);
    const finding = await engine.repo.getFinding(findingId);
    if (!finding) throw new CliError(`finding ${findingId} not found`);
    const assessments = await engine.repo.assessmentsForFinding(findingId);
    const occurrences = await engine.repo.occurrencesForFinding(findingId);
    const latest = assessments.at(-1);
    const occurrence = occurrences.at(-1);
    const evidence = await engine.repo.getEvidence(occurrence?.evidenceIds ?? []);
    const dispositions = (await engine.repo.listDispositions(finding.projectId)).filter(
      (d) => d.findingId === findingId,
    );
    const active = activeDispositions(dispositions, new Date()).get(findingId);
    const runs = await engine.repo.listAgentRuns({ findingId });
    const explanation = runs.filter((r) => r.role === 'explain' && r.status === 'COMPLETED').at(-1);
    const candidate = (await engine.repo.listCandidates(occurrence?.scanId ?? '')).find((c) =>
      occurrence?.candidateIds.includes(c.candidateId),
    );
    if (options.json) {
      process.stdout.write(
        `${JSON.stringify({ finding, assessments, occurrences, evidence, dispositions, agentRuns: runs }, null, 2)}\n`,
      );
      return EXIT.OK;
    }
    const lines = [
      `${pc.bold(finding.findingId)}  ${latest ? severityLabel(latest.severity) : ''} ${finding.title}`,
      `${pc.dim('category')}    ${finding.category} ${finding.cwe.join(', ')}`,
      `${pc.dim('location')}    ${occurrence ? occurrence.locations.map((l) => `${l.path}:${l.startLine} (${l.role})`).join(', ') : '-'}`,
      `${pc.dim('rules')}       ${occurrence?.ruleIds.join(', ') ?? '-'}`,
      ...(candidate?.package ? [`${pc.dim('package')}     ${candidate.package.purl}`] : []),
      ...(candidate?.vulnerabilityIds ? [`${pc.dim('advisories')}  ${candidate.vulnerabilityIds.join(', ')}`] : []),
      `${pc.dim('status')}      ${latest ? `${latest.reconciliationState.toLowerCase()} · ${latest.classification.toLowerCase()} · ${latest.verificationLevel}` : '-'}`,
      ...(active ? [`${pc.dim('disposition')} ${describeDisposition(active)}`] : []),
      `${pc.dim('fingerprint')} ${finding.canonicalFingerprint} (${finding.fingerprintAlgorithm})`,
      '',
      pc.bold('History'),
      ...assessments.map(
        (a) =>
          `  ${a.assessedAt}  ${a.scanId}  ${a.reconciliationState.toLowerCase().padEnd(22)} ${a.severity.padEnd(8)} ${a.changeCauses.join(',').toLowerCase()}`,
      ),
    ];
    if (latest) {
      lines.push(
        '',
        pc.bold('Assessment'),
        `  ${latest.reasoningSummary}`,
        ...latest.missingEvidence.map((m) => `  ${pc.yellow('missing:')} ${m}`),
      );
    }
    if (explanation?.output) {
      const ai = explanation.output as AiExplanation;
      lines.push(
        '',
        pc.bold(`AI explanation (${explanation.modelsUsed.join(', ')}, ${explanation.completedAt})`),
        `  ${ai.classification.toLowerCase()} · ${ai.severity} · confidence ${ai.confidence.toLowerCase()}`,
        `  ${ai.summary}`,
        `  ${pc.dim('remediation')} ${ai.remediation.strategy}`,
        ...ai.remediation.steps.map((s, i) => `    ${i + 1}. ${s}`),
      );
    }
    for (const e of evidence) if (e.excerpt) lines.push('', pc.bold(e.summary), e.excerpt);
    process.stdout.write(`${lines.join('\n')}\n`);
    return EXIT.OK;
  });
}

const KINDS: Record<string, Disposition['kind']> = {
  'false-positive': 'FALSE_POSITIVE',
  'accepted-risk': 'ACCEPTED_RISK',
  'wont-fix': 'WONT_FIX',
  duplicate: 'DUPLICATE_OF',
};

export async function findingsDisposeCommand(
  findingId: string,
  path: string | undefined,
  options: CommonOptions & { as: string; reason: string; expires?: string; duplicateOf?: string; by?: string },
): Promise<number> {
  const kind = KINDS[options.as];
  if (!kind) throw new CliError(`unknown disposition "${options.as}" (expected ${Object.keys(KINDS).join(', ')})`);
  const expiresAt = options.expires ? parseExpiry(options.expires) : undefined;
  if (kind === 'ACCEPTED_RISK' && !expiresAt) throw new CliError('accepted risk needs --expires (for example 30d)');
  return withEngine(path, options, async (engine) => {
    await requireFinding(engine, findingId, path);
    try {
      const disposition = await disposeFinding(engine.repo, systemClock, {
        findingId,
        kind,
        reason: options.reason,
        decidedBy: options.by ?? currentUser(),
        ...(expiresAt ? { expiresAt } : {}),
        ...(options.duplicateOf ? { duplicateOf: options.duplicateOf } : {}),
      });
      if (options.json) process.stdout.write(`${JSON.stringify(disposition, null, 2)}\n`);
      else process.stdout.write(`${pc.green('recorded')} ${findingId}: ${describeDisposition(disposition)}\n`);
      return EXIT.OK;
    } catch (err) {
      if (err instanceof SpinxscaError) throw new CliError(err.message);
      throw err;
    }
  });
}

function parseExpiry(value: string): string {
  const days = /^(\d+)d$/.exec(value);
  if (days) return new Date(Date.now() + Number(days[1]) * 86_400_000).toISOString();
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new CliError(`invalid --expires "${value}" (use 30d or an ISO date)`);
  return date.toISOString();
}

function describeDisposition(d: Disposition): string {
  return `${d.kind.toLowerCase().replace(/_/g, ' ')} by ${d.decidedBy}: ${d.reason}${d.expiresAt ? ` (expires ${d.expiresAt})` : ''}${d.duplicateOf ? ` (duplicate of ${d.duplicateOf})` : ''}`;
}
