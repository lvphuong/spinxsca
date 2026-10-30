import type { ScanReportModel } from '@spinxsca/core';

const MAX_ROWS = 25;

/** Short Markdown for a pull request comment: new findings first, everything else as counts. */
export function renderPrComment(
  model: ScanReportModel,
  options: { policyPassed?: boolean; reportUrl?: string } = {},
): string {
  const fresh = model.present.filter((e) =>
    ['NEW', 'REOPENED', 'NEEDS_RECONCILIATION'].includes(e.assessment.reconciliationState),
  );
  const existing = model.present.length - fresh.length;
  const summary = model.scan.summary;
  const coverage = summary?.completeness ?? 'UNKNOWN';
  const lines: string[] = ['<!-- spinxsca -->', '## spinxsca security review', ''];
  const verdict =
    options.policyPassed === undefined ? '' : options.policyPassed ? ' · ✅ policy passed' : ' · ❌ policy failed';
  lines.push(
    `**${fresh.length} new**, ${existing} existing, ${model.resolved.length} resolved, ${model.notReevaluated.length} not re-evaluated · coverage ${coverage}${verdict}`,
    '',
  );
  if (fresh.length > 0) {
    lines.push('| Severity | Finding | Location | Status |', '|---|---|---|---|');
    for (const e of fresh.slice(0, MAX_ROWS)) {
      const loc = e.occurrence?.locations[0];
      const status = `${e.assessment.classification.toLowerCase()} · ${e.assessment.verificationLevel.replace('_', ' ').toLowerCase()}`;
      lines.push(
        `| ${e.assessment.severity} | \`${e.finding.findingId}\` ${escapeCell(e.finding.title)} | \`${loc ? `${loc.path}:${loc.startLine}` : '-'}\` | ${status} |`,
      );
    }
    if (fresh.length > MAX_ROWS) lines.push(`| … | ${fresh.length - MAX_ROWS} more | | |`);
    lines.push('');
    for (const e of fresh.slice(0, 5)) {
      const ai = e.explanation?.output;
      if (!ai) continue;
      lines.push(
        `<details><summary><code>${e.finding.findingId}</code> ${escapeCell(e.finding.title)}</summary>`,
        '',
        escapeCell(ai.summary),
        '',
        `**Fix:** ${escapeCell(ai.remediation.strategy)}`,
        '',
        '</details>',
        '',
      );
    }
  } else lines.push('No new findings in this change.', '');
  if (model.resolved.length)
    lines.push(`Resolved: ${model.resolved.map((e) => `\`${e.finding.findingId}\``).join(', ')}`, '');
  if (coverage !== 'COMPLETE')
    lines.push('> Coverage is partial: absence of findings does not establish that the change is clean.', '');
  lines.push(
    `<sub>scan \`${model.scan.scanId}\` · ${model.scan.mode.toLowerCase()} · baseline ${model.scan.baselineScanId ? `\`${model.scan.baselineScanId}\`` : 'none'}${options.reportUrl ? ` · [full report](${options.reportUrl})` : ''}</sub>`,
  );
  return `${lines.join('\n')}\n`;
}

function escapeCell(text: string): string {
  return text.replace(/\|/g, '\\|').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, ' ');
}
