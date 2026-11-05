import type { DependencyInfo, ResourceMatrix } from '@spinxsca/core';
import { renderGroup } from '@spinxsca/core';
import type { CaseHandle, FindingClaim, GroundTruth, Objective, PocOracle, WorkItem } from '@spinxsca/schemas';
import { renderGroundTruth, sliceFor } from '../ground-truth';
import type { FindingsDeliverable } from './deliverables';

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
  /** Ground truth of the case once the RECON item is done (ADR-049). */
  groundTruth?: GroundTruth;
  matrix?: ResourceMatrix;
  /** Operator context pack (ADR-051), already rendered. */
  operatorContext?: string;
  /** Agent-reported handles with their claims (for the critic's "already reported" list). */
  agentHandles?: () => ReadonlyArray<{
    handle: string;
    title: string;
    path: string;
    startLine: number;
    itemId?: string;
  }>;
  /** Validated deliverable of another item (the critic reads the subject item's checklist and hunt log). */
  itemResult?: (itemId: string) => Promise<unknown>;
}

const SUBMIT: Partial<Record<WorkItem['kind'], string>> = {
  TRIAGE_FINDING: 'submit_triage',
  DEPENDENCY_APPLICABILITY: 'submit_applicability',
  EXPLOIT_POC: 'submit_poc',
  REVIEW_POC: 'submit_poc_review',
  RECON: 'submit_recon',
};

const CRITIC_CONTEXT_CAP = 12_000;
const PATH_LINE = /([\w./-]+\.[A-Za-z0-9]+):(\d+)/g;

/** Files an item is about, from its description (route lists, census rows) and handles. */
export function itemPaths(item: WorkItem, handles: ReadonlyArray<CaseHandle | undefined>): string[] {
  const paths = new Set<string>();
  for (const m of item.description.matchAll(PATH_LINE)) paths.add(m[1] as string);
  for (const h of handles) if (h) paths.add(h.path);
  return [...paths];
}

/** Ground-truth slice of an item: its files, plus the family or group named in the title. */
export function sliceForItem(
  gt: GroundTruth,
  item: WorkItem,
  handles: ReadonlyArray<CaseHandle | undefined>,
): GroundTruth {
  const familyIds = [...item.title.matchAll(/\bFAM-\d+\b/g), ...item.description.matchAll(/\bFAM-\d+\b/g)].map(
    (m) => m[0],
  );
  const invariantIds = [...item.description.matchAll(/\bINV-\d+\b/g)].map((m) => m[0]);
  const paths = itemPaths(item, handles);
  if (!paths.length && !familyIds.length && !invariantIds.length) return gt;
  return sliceFor(gt, { paths, familyIds, invariantIds });
}

function censusFor(matrix: ResourceMatrix | undefined, paths: readonly string[]): string {
  if (!matrix || !paths.length) return '';
  const set = new Set(paths);
  const groups = matrix.groups.filter((g) => g.rows.some((r) => set.has(r.path)));
  if (!groups.length) return '';
  return `Census rows for these files (heuristic evidence, not findings):\n${groups.map(renderGroup).join('\n\n')}`.slice(
    0,
    3000,
  );
}

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
  if (item.kind === 'RECON') {
    parts.push(`Codebase: ${ctx.snapshotSize} files, ${ctx.endpointCount} endpoints in the index.`);
    if (ctx.operatorContext) parts.push(ctx.operatorContext);
  }
  const handles = item.handles.map((h) => ctx.handle(h));
  if (ctx.groundTruth) {
    const gt = ctx.groundTruth;
    if (['THREAT_PACKET', 'LOGIC_AUDIT', 'HYPOTHESIS', 'VARIANT_HUNT', 'COMPLETENESS_CRITIC'].includes(item.kind)) {
      parts.push(renderGroundTruth(sliceForItem(gt, item, handles)));
      const census = censusFor(ctx.matrix, itemPaths(item, handles));
      if (census) parts.push(census);
    } else if (item.kind === 'BASELINE_AUDIT' && gt.carveouts.length) {
      // The baseline auditor stays blind to the threat model; it only gets the carve-outs (ADR-024, ADR-049).
      parts.push(renderGroundTruth(gt, { sections: ['carveouts'] }));
    } else if (item.kind === 'TRIAGE_FINDING') {
      const handle = handles[0];
      const claim = (handle?.draft as { claim?: FindingClaim } | undefined)?.claim;
      if (claim)
        parts.push(
          `<claim_contract reporter="${handle?.producer?.persona ?? 'agent'}">\n${JSON.stringify(claim, null, 2)}\n</claim_contract>`,
        );
      const refs = {
        ...(claim?.invariantId ? { invariantIds: [claim.invariantId] } : {}),
        ...(claim?.familyId ? { familyIds: [claim.familyId] } : {}),
        paths: handle ? [handle.path] : [],
      };
      const slice = sliceFor(gt, refs);
      parts.push(renderGroundTruth({ ...slice, carveouts: gt.carveouts }, { maxChars: 4000 }));
      const census = censusFor(ctx.matrix, handle ? [handle.path] : []);
      if (census) parts.push(census);
    }
    if (ctx.operatorContext && item.kind !== 'RECON') parts.push(ctx.operatorContext);
  }
  if (item.kind === 'COMPLETENESS_CRITIC') {
    const reported = (ctx.agentHandles?.() ?? []).filter((h) => !item.subjectItemId || h.itemId === item.subjectItemId);
    parts.push(
      `Already reported for this item (do NOT repeat):\n${reported.length ? reported.map((h) => `- ${h.handle} ${h.title} (${h.path}:${h.startLine})`).join('\n') : '(none)'}`,
    );
    const prior = item.subjectItemId
      ? ((await ctx.itemResult?.(item.subjectItemId)) as Partial<FindingsDeliverable> | undefined)
      : undefined;
    if (prior) {
      parts.push(
        `Checklist and hunt log produced so far:\n${JSON.stringify({ invariantResults: prior.invariantResults ?? [], variantLog: prior.variantLog ?? [], notes: prior.notes ?? '' }).slice(0, CRITIC_CONTEXT_CAP)}`,
      );
    }
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
