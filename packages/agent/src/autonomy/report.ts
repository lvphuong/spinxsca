import { latestVerdicts } from '@spinxsca/core';
import type {
  CaseHandle,
  CaseLedger,
  CaseVerdict,
  CoverageCheck,
  GroundTruth,
  Objective,
  ReviewCase,
  WorkItem,
} from '@spinxsca/schemas';

/** Markdown report of a review case: what was asked, what was done, what was concluded, what was not. */
export function caseReport(o: {
  rc: ReviewCase;
  objectives: readonly Objective[];
  items: readonly WorkItem[];
  handles: readonly CaseHandle[];
  verdicts: readonly CaseVerdict[];
  checks: readonly CoverageCheck[];
  ledger: CaseLedger;
  pendingApprovals: number;
  /** Ground truth written by the recon item (ADR-049). */
  groundTruth?: GroundTruth;
  /** Review questions waiting for a human (ADR-051): id and question only. */
  openQuestions?: ReadonlyArray<{ id: string; question: string }>;
}): string {
  const esc = (s: string) => s.replace(/\|/g, '\\|').replace(/\n/g, ' ');
  const latest = latestVerdicts(o.verdicts);
  const rows = o.handles.map((h) => {
    const v = latest.get(h.handle);
    const level = v ? (v.poc?.outcome === 'CONFIRMED' ? 'L3' : 'L2') : '-';
    const app = v?.applicability
      ? ` ${v.applicability.status}${v.applicability.reachability ? `/${v.applicability.reachability}` : ''}`
      : '';
    return `| ${h.handle} | ${esc(h.title)} | ${h.path}:${h.startLine} | ${v?.verdict ?? 'UNREVIEWED'}${app} | ${v?.severity ?? h.severity} | ${level} |`;
  });
  const items = o.items.filter((i) => i.persona !== 'host');
  return [
    `# Review case ${o.rc.caseId}`,
    '',
    `Status: **${o.rc.status}**${o.rc.stopReason ? ` (${o.rc.stopReason})` : ''} · mode ${o.rc.mode}${o.rc.attended ? ', attended' : ', unattended'} · rounds ${o.rc.round}`,
    `Cost: $${o.ledger.costUsd.toFixed(2)}${o.ledger.unpriced ? ' (lower bound: unpriced model)' : ''} · model calls ${o.ledger.modelCalls} · sandbox runs ${o.ledger.sandboxRuns}`,
    ...(o.pendingApprovals ? [`Waiting for a human: ${o.pendingApprovals} approval(s) in the inbox`] : []),
    '',
    '## Objectives',
    ...o.objectives.map((x) => `- [${x.status}] ${x.title}${x.reason ? ` — ${x.reason}` : ''}`),
    '',
    '## Findings',
    '| Handle | Title | Location | Verdict | Severity | Level |',
    '|---|---|---|---|---|---|',
    ...rows,
    '',
    '## Work',
    `${items.filter((i) => i.status === 'done').length}/${items.length} items done`,
    ...items
      .filter((i) => i.status !== 'done')
      .map(
        (i) => `- ${i.itemId.split(':').pop()} ${i.kind} [${i.status}]${i.blockedReason ? `: ${i.blockedReason}` : ''}`,
      ),
    '',
    '## Coverage',
    ...o.checks.map((c) => `- ${c.checkId}: ${c.outcome}${c.reason ? ` — ${c.reason}` : ''}`),
    ...(o.groundTruth
      ? [
          '',
          '## Ground truth',
          `Archetype: ${o.groundTruth.archetype}${o.groundTruth.archetypeNote ? ` (${esc(o.groundTruth.archetypeNote)})` : ''} · ${o.groundTruth.invariants.length} invariants · ${o.groundTruth.baselines.length} baseline references · ${o.groundTruth.families.length} variant families (${o.groundTruth.families.reduce((n, f) => n + f.members.length, 0)} members) · ${o.groundTruth.carveouts.length} carve-outs`,
          ...o.groundTruth.residualUnknowns.map((u) => `- ${u.unknownId} [${u.kind}] ${esc(u.question)}`),
        ]
      : []),
    ...(o.openQuestions?.length
      ? ['', '## Open questions', ...o.openQuestions.map((q) => `- ${q.id}: ${esc(q.question)}`)]
      : []),
  ].join('\n');
}
