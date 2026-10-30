import { FINGERPRINT_ALGORITHM, type ReportEntry, type ScanReportModel } from '@spinxsca/core';
import type { ScanTask, Severity } from '@spinxsca/schemas';

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/** Human-readable assessment report. Every statement is derived from stored records. */
export function renderMarkdown(model: ScanReportModel): string {
  const { scan, snapshot } = model;
  const m = scan.manifest;
  const lines: string[] = [];
  lines.push('# Security Assessment Report', '');
  lines.push(`**Project:** ${escapeMd(model.project.name)}  `);
  lines.push(`**Scan:** \`${scan.scanId}\` (${scan.mode}, ${scan.status})  `);
  lines.push(`**Requested:** ${scan.requestedAt}${scan.completedAt ? ` · completed ${scan.completedAt}` : ''}`, '');

  lines.push('## Analysis manifest', '');
  lines.push('| Input | Version |', '|---|---|');
  lines.push(
    `| Source | ${snapshot.kind}${snapshot.commitSha ? ` \`${snapshot.commitSha.slice(0, 12)}\`` : ''} · ${snapshot.fileCount} files · \`${short(snapshot.contentManifestDigest)}\` |`,
  );
  for (const s of m.scannerBundle.scanners)
    lines.push(`| Scanner | ${s.id} ${s.toolVersion} (\`${s.image.split('@')[1]?.slice(0, 19) ?? s.image}\`) |`);
  for (const r of m.ruleBundles)
    lines.push(`| Rule bundle | ${r.id} · ${r.ruleCount} rules · \`${short(r.digest)}\` |`);
  lines.push(`| Knowledge base | ${m.knowledgeBase ? `\`${m.knowledgeBase.snapshotId}\`` : 'not used (phase 0)'} |`);
  lines.push(
    `| AI policy | ${m.aiPolicy.level === 'off' ? 'off — findings are static evidence only (L1)' : m.aiPolicy.level} |`,
  );
  lines.push(`| Baseline | ${scan.baselineScanId ? `\`${scan.baselineScanId}\`` : 'none (first assessment)'} |`);
  lines.push(`| Manifest digest | \`${short(scan.manifestDigest)}\` |`, '');

  lines.push('## Summary', '');
  const summary = scan.summary;
  lines.push(`Coverage: **${summary?.completeness ?? 'UNKNOWN'}**. Findings present: **${model.present.length}**.`, '');
  lines.push('| Severity | Present | New |', '|---|---:|---:|');
  for (const sev of SEVERITIES) {
    const present = model.present.filter((e) => e.assessment.severity === sev);
    const fresh = present.filter((e) => ['NEW', 'REOPENED'].includes(e.assessment.reconciliationState));
    if (present.length > 0) lines.push(`| ${sev} | ${present.length} | ${fresh.length} |`);
  }
  if (model.present.length === 0) lines.push('| — | 0 | 0 |');
  lines.push('');
  const states = summary?.byState ?? {};
  lines.push(
    `Delta vs baseline: ${
      Object.entries(states)
        .map(([state, count]) => `${state.toLowerCase().replace(/_/g, ' ')} ${count}`)
        .join(', ') || 'no findings'
    }.`,
    '',
  );
  if (summary?.completeness !== 'COMPLETE') {
    lines.push(
      '> Coverage is not complete. Absence of findings does not establish that the code is free of these issues.',
      '',
    );
  }

  if (model.present.length > 0) {
    lines.push('## Findings', '');
    for (const entry of model.present) lines.push(...renderEntry(entry), '');
  }
  if (model.suppressed.length > 0) {
    lines.push('## Suppressed by disposition', '');
    for (const e of model.suppressed) {
      const d = e.disposition;
      lines.push(
        `- \`${e.finding.findingId}\` ${escapeMd(e.finding.title)} — ${d?.kind.toLowerCase().replace(/_/g, ' ')} by ${escapeMd(d?.decidedBy ?? '')}: ${escapeMd(d?.reason ?? '')}${d?.expiresAt ? ` (expires ${d.expiresAt})` : ''}`,
      );
    }
    lines.push('');
  }
  if (model.resolved.length > 0) {
    lines.push('## Resolved since baseline', '');
    for (const e of model.resolved)
      lines.push(
        `- \`${e.finding.findingId}\` ${escapeMd(e.finding.title)} — ${escapeMd(e.assessment.reasoningSummary)}`,
      );
    lines.push('');
  }
  if (model.notReevaluated.length > 0) {
    lines.push('## Carried forward (not re-evaluated)', '');
    lines.push(
      'These findings were open in the baseline but this scan did not cover them, so they are neither confirmed nor resolved.',
      '',
    );
    for (const e of model.notReevaluated)
      lines.push(
        `- \`${e.finding.findingId}\` ${escapeMd(e.finding.title)} — ${escapeMd(e.assessment.reasoningSummary)}`,
      );
    lines.push('');
  }

  lines.push('## Coverage', '');
  lines.push('| Task | Status | Files analysed | Rules | Tool errors |', '|---|---|---:|---:|---:|');
  for (const task of model.tasks) lines.push(taskRow(task));
  lines.push('');
  if (model.aiRuns.length > 0) {
    const cost = model.aiRuns.reduce((n, r) => n + (r.costUsd ?? 0), 0);
    const tokens = model.aiRuns.reduce((n, r) => n + r.usage.inputTokens + r.usage.outputTokens, 0);
    const models = [...new Set(model.aiRuns.flatMap((r) => r.modelsUsed))].join(', ');
    lines.push('## AI usage', '');
    lines.push(
      `${model.aiRuns.length} run(s) · models ${models || 'n/a'} · ${tokens} tokens · ${cost > 0 ? `$${cost.toFixed(4)}` : 'cost not priced'} · prompt bundle \`${short(model.aiRuns[0]?.promptBundleDigest ?? '')}\``,
      '',
    );
    const failed = model.aiRuns.filter((r) => r.status !== 'COMPLETED');
    for (const r of failed)
      lines.push(`- ${r.findingId ?? r.role}: ${r.status.toLowerCase()}${r.error ? ` (${escapeMd(r.error)})` : ''}`);
    if (failed.length) lines.push('');
  }
  lines.push(
    '---',
    `Generated by spinxsca from scan records. Fingerprint algorithm: \`${FINGERPRINT_ALGORITHM}\`.`,
    '',
  );
  return lines.join('\n');
}

function renderEntry(entry: ReportEntry): string[] {
  const { finding, assessment, occurrence } = entry;
  const primary = occurrence?.locations[0];
  const out = [
    `### ${finding.findingId} · ${assessment.severity} · ${escapeMd(finding.title)}`,
    '',
    `- **Location:** ${primary ? `\`${primary.path}:${primary.startLine}\`` : 'unknown'}`,
    `- **Category:** ${finding.category}${finding.cwe.length ? ` (${finding.cwe.join(', ')})` : ''}`,
    `- **Status:** ${assessment.reconciliationState.toLowerCase().replace(/_/g, ' ')} · ${assessment.classification.toLowerCase()} · verification ${assessment.verificationLevel} · confidence ${assessment.confidence.toLowerCase()}`,
    `- **Rules:** ${(occurrence?.ruleIds ?? []).map((r) => `\`${r}\``).join(', ')}`,
    `- **First seen:** \`${finding.firstSeenScanId}\``,
  ];
  if (assessment.changeCauses.length > 0)
    out.push(`- **Why it appears:** ${assessment.changeCauses.join(', ').toLowerCase().replace(/_/g, ' ')}`);
  const intel = describeIntel(assessment.intel);
  if (intel) out.push(`- **Exploitation intel:** ${intel}`);
  const message = entry.candidates[0]?.message;
  if (message) out.push('', escapeMd(message));
  const ai = entry.explanation?.output;
  if (ai) {
    out.push('', `**AI assessment** (${assessment.assessedBy}): ${escapeMd(ai.summary)}`);
    const path = [ai.attackPath.attacker, ai.attackPath.entryPoint, ai.attackPath.source, ai.attackPath.sink].filter(
      Boolean,
    );
    out.push('', `- **Attack path:** ${escapeMd(path.join(' / '))}`);
    if (ai.attackPath.controls.length) out.push(`- **Controls:** ${escapeMd(ai.attackPath.controls.join('; '))}`);
    out.push(`- **Severity rationale:** ${escapeMd(ai.severityRationale)}`);
    if (ai.counterevidence.length) out.push(`- **Counterevidence:** ${escapeMd(ai.counterevidence.join('; '))}`);
    out.push(
      '',
      `**Remediation:** ${escapeMd(ai.remediation.strategy)}`,
      ...ai.remediation.steps.map((s, i) => `${i + 1}. ${escapeMd(s)}`),
    );
    if (ai.remediation.example) out.push('', '```', ai.remediation.example, '```');
  }
  for (const evidence of entry.evidence) {
    if (evidence.excerpt)
      out.push(
        '',
        `<details><summary>${escapeMd(evidence.summary)}</summary>`,
        '',
        '```',
        evidence.excerpt,
        '```',
        '',
        '</details>',
      );
  }
  if (assessment.missingEvidence.length > 0)
    out.push('', `_Missing evidence:_ ${escapeMd(assessment.missingEvidence.join(' '))}`);
  return out;
}

function taskRow(task: ScanTask): string {
  const c = task.coverage;
  const files = c ? `${c.files.analyzed}/${c.files.total}` : '—';
  const rules = c?.rules ? String(c.rules.executed) : '—';
  const errors = c ? String(c.toolErrors.length) : '—';
  const status = task.error ? `${task.status} (${escapeMd(task.error.slice(0, 80))})` : task.status;
  return `| ${task.scannerId ?? task.name} | ${status} | ${files} | ${rules} | ${errors} |`;
}

function short(digest: string): string {
  return digest.replace('sha256:', '').slice(0, 12);
}

function escapeMd(text: string): string {
  return text.replace(/\|/g, '\\|').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** KEV, EPSS and CVSS side by side, in triage order (docs/architecture/04 section 5). */
export function describeIntel(intel: ReportEntry['assessment']['intel']): string | undefined {
  if (!intel) return undefined;
  const parts: string[] = [];
  if (intel.kev)
    parts.push(
      `**CISA KEV** since ${intel.kev.dateAdded}${intel.kev.ransomware ? ' (ransomware use known)' : ''}${intel.kev.dueDate ? `, federal due date ${intel.kev.dueDate}` : ''}`,
    );
  if (intel.epss)
    parts.push(
      `EPSS ${intel.epss.score.toFixed(3)} (percentile ${(intel.epss.percentile * 100).toFixed(0)}, ${intel.epss.date.slice(0, 10)})`,
    );
  if (intel.cvss) parts.push(`CVSS ${intel.cvss.version} ${intel.cvss.baseScore} \`${intel.cvss.vector}\``);
  return parts.length ? `${parts.join(' · ')} — ${intel.cves.join(', ')}` : undefined;
}
