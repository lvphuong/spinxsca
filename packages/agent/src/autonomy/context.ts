import type { DependencyInfo } from '@spinxsca/core';
import type { CaseHandle, Objective, PocOracle, WorkItem } from '@spinxsca/schemas';

export interface ItemPromptContext {
  goal: string;
  objectives: readonly Objective[];
  handle: (h: string) => CaseHandle | undefined;
  /** Redacted evidence excerpt of a handle. */
  evidence: (h: string) => Promise<string>;
  inventory: () => Promise<readonly DependencyInfo[]>;
  snapshotSize: number;
  endpointCount: number;
  duplicates: readonly string[][];
  historySummary?: string;
}

const SUBMIT: Partial<Record<WorkItem['kind'], string>> = {
  TRIAGE_FINDING: 'submit_triage',
  DEPENDENCY_APPLICABILITY: 'submit_applicability',
  EXPLOIT_POC: 'submit_poc',
  REVIEW_POC: 'submit_poc_review',
};

/** Oracle the host expects per category of a runtime-verifiable finding (ADR-045). */
export const ORACLE_FOR_CATEGORY: Readonly<Record<string, PocOracle>> = {
  PATH_TRAVERSAL: 'CANARY_READ',
  COMMAND_INJECTION: 'COMMAND_MARKER',
  CODE_INJECTION: 'COMMAND_MARKER',
  XSS: 'UNESCAPED_REFLECTION',
  SQL_INJECTION: 'DATA_DIFFERENTIAL',
};

export const ORACLE_GUIDE: Readonly<Record<PocOracle, string>> = {
  CANARY_READ:
    'Make the vulnerable code read the file named by process.env.SPX_CANARY_PATH (build a traversal from it) and print what the code returns.',
  COMMAND_MARKER:
    'Make the injected command create the file named by process.env.SPX_COMMAND_MARKER (for example `; touch <that path>`); the host checks that the file exists.',
  UNESCAPED_REFLECTION:
    'Pass `<spx-` + SPX_NONCE + `>` as the input and print the rendered output; it counts only when it comes back unescaped.',
  DATA_DIFFERENTIAL:
    'Seed a record the caller must not see whose value is `SPX-ROW-` followed by SPX_NONCE, call the vulnerable query as the caller and print the result.',
};

function handleLine(h: CaseHandle): string {
  return [
    `Handle: ${h.handle}`,
    `Title: ${h.title}`,
    `Category: ${h.category}`,
    `Scanner: ${h.scanner} rule ${h.ruleId}`,
    `Location: ${h.path}:${h.startLine}`,
    `Severity: ${h.severity}`,
    ...(h.packagePurl ? [`Package: ${h.packagePurl}`] : []),
    ...(h.vulnerabilityIds.length ? [`Advisories: ${h.vulnerabilityIds.join(', ')}`] : []),
    ...(h.origin === 'agent'
      ? [`Reported by: ${h.producer?.persona ?? 'an agent'} (you must judge it independently)`]
      : []),
  ].join('\n');
}

/** Task prompt of one work item; the persona system prompt carries the method and the rules. */
export async function itemPrompt(item: WorkItem, ctx: ItemPromptContext): Promise<string> {
  const parts: string[] = [`<operator_goal>\n${ctx.goal}\n</operator_goal>`, `Work item: ${item.kind} — ${item.title}`];
  if (item.description) parts.push(`<item_details untrusted="false">\n${item.description}\n</item_details>`);
  for (const h of item.handles) {
    const handle = ctx.handle(h);
    if (!handle) continue;
    parts.push(handleLine(handle));
    if (item.kind === 'TRIAGE_FINDING') parts.push(`Evidence recorded by the host:\n${await ctx.evidence(h)}`);
    if (item.kind === 'DEPENDENCY_APPLICABILITY' && handle.packagePurl) {
      const name = decodeURIComponent(handle.packagePurl.replace(/^pkg:[^/]+\//, '').replace(/@[^@]*$/, ''));
      const records = (await ctx.inventory()).filter(
        (d) => d.name === name || d.name.endsWith(`/${name}`) || d.purl === handle.packagePurl,
      );
      parts.push(
        records.length
          ? `Lockfile records:\n${records.map((d) => `- ${d.ecosystem} ${d.name}@${d.version} ${d.direct === undefined ? '' : d.direct ? 'direct' : 'transitive'} ${d.scope} (${d.manifestPath})`).join('\n')}`
          : 'Lockfile records: none found for this package.',
      );
    }
  }
  if (item.kind === 'BASELINE_AUDIT') {
    parts.push(`Codebase: ${ctx.snapshotSize} files, ${ctx.endpointCount} endpoints in the index.`);
  }
  if (item.kind === 'SECRETS_SWEEP' && ctx.historySummary) parts.push(`Git history scan: ${ctx.historySummary}`);
  const dupes = ctx.duplicates.filter((g) => g.some((h) => item.handles.includes(h)));
  if (dupes.length)
    parts.push(`Possible duplicates (same category, nearby lines): ${dupes.map((g) => g.join(' ~ ')).join('; ')}`);
  parts.push(`Case objectives:\n${ctx.objectives.map((o) => `- ${o.title}`).join('\n')}`);
  parts.push(`Finish by calling \`${SUBMIT[item.kind] ?? 'submit_findings'}\`.`);
  return parts.join('\n\n');
}

export function leadPrompt(o: { goal: string; round: number; board: string; journal: string; budget: string }): string {
  return [
    `<operator_goal>\n${o.goal}\n</operator_goal>`,
    `Round ${o.round}. Budget: ${o.budget}.`,
    o.board,
    o.journal ? `## Journal (latest)\n${o.journal}` : '',
    'Decide what optional work, if any, raises the value of this review now (variant hunts after a confirmed finding, a PoC for a confirmed runtime-verifiable finding, a hypothesis for an unexplored risk). Then call `submit_plan`.',
  ]
    .filter(Boolean)
    .join('\n\n');
}
