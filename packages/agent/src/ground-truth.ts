import type { GroundTruthCoverage } from '@spinxsca/core';
import {
  type AiContextConfig,
  type AiFinding,
  type Carveout,
  GroundTruth,
  type InvariantResult,
  type VariantHuntRow,
} from '@spinxsca/schemas';
import { type CodeToolContext, checkCitations } from './tools/code-tools';

/**
 * Ground truth helpers shared by the standard investigation and the autonomous case (ADR-049):
 * slicing per packet or file, rendering into prompts with a hard size cap, host-side validation of
 * the recon deliverable, and the closed-ended checks that turn "did you look everywhere" into
 * problems the model must fix before its submission is accepted.
 */
export interface SliceKeys {
  packetIds?: readonly string[];
  paths?: readonly string[];
  invariantIds?: readonly string[];
  familyIds?: readonly string[];
}

export type GroundTruthSection = 'claims' | 'invariants' | 'baselines' | 'families' | 'carveouts' | 'unknowns';

const ALL_SECTIONS: readonly GroundTruthSection[] = [
  'claims',
  'invariants',
  'baselines',
  'families',
  'carveouts',
  'unknowns',
];

export function emptyGroundTruth(archetype: GroundTruth['archetype'] = 'hybrid'): GroundTruth {
  return GroundTruth.parse({ archetype });
}

/** The part of the ground truth one reviewer needs: its packets' invariants, the families it touches, every carve-out. */
export function sliceFor(gt: GroundTruth, keys: SliceKeys): GroundTruth {
  const paths = new Set(keys.paths ?? []);
  const packets = new Set(keys.packetIds ?? []);
  const invariantIds = new Set(keys.invariantIds ?? []);
  const familyIds = new Set(keys.familyIds ?? []);
  const any = paths.size + packets.size + invariantIds.size + familyIds.size > 0;
  if (!any) return gt;
  const families = gt.families.filter((f) => familyIds.has(f.familyId) || f.members.some((m) => paths.has(m.path)));
  const familySet = new Set(families.map((f) => f.familyId));
  const invariants = gt.invariants.filter(
    (i) =>
      invariantIds.has(i.invariantId) ||
      i.packets.some((p) => packets.has(p)) ||
      paths.has(i.location.path) ||
      (i.familyId !== undefined && familySet.has(i.familyId)),
  );
  for (const i of invariants) if (i.familyId) familySet.add(i.familyId);
  const allFamilies = gt.families.filter((f) => familySet.has(f.familyId));
  const baselineIds = new Set(allFamilies.map((f) => f.baselineId).filter((b): b is string => !!b));
  const baselines = gt.baselines.filter((b) => baselineIds.has(b.baselineId) || paths.has(b.location.path));
  const affected = new Set([...invariants.map((i) => i.invariantId), ...allFamilies.map((f) => f.familyId)]);
  const residualUnknowns = gt.residualUnknowns.filter((u) => u.affects.some((a) => affected.has(a)));
  return {
    ...gt,
    invariants,
    baselines,
    families: allFamilies,
    residualUnknowns,
  };
}

const span = (s: { path: string; startLine: number; endLine: number }) =>
  s.startLine === s.endLine ? `${s.path}:${s.startLine}` : `${s.path}:${s.startLine}-${s.endLine}`;

/** Markdown rendering of a (sliced) ground truth for a prompt, wrapped as untrusted recon output. */
export function renderGroundTruth(
  gt: GroundTruth,
  options: { maxChars?: number; sections?: readonly GroundTruthSection[] } = {},
): string {
  const maxChars = options.maxChars ?? 6000;
  const sections = new Set(options.sections ?? ALL_SECTIONS);
  const blocks: string[] = [];
  blocks.push(`Archetype: ${gt.archetype}${gt.archetypeNote ? ` — ${gt.archetypeNote}` : ''}`);
  if (sections.has('claims') && gt.trustClaims.length) {
    blocks.push(
      `### Trust claims (${gt.trustClaims.length}; "claimed" facts must be rechecked)\n${gt.trustClaims
        .map((c) => `- [${c.confidence}] ${c.statement} (${c.provenance})`)
        .join('\n')}`,
    );
  }
  if (sections.has('invariants') && gt.invariants.length) {
    blocks.push(
      `### Invariant checklist (${gt.invariants.length}; report each as PASS, FAIL or UNKNOWN)\n${gt.invariants
        .map(
          (i) =>
            `- ${i.invariantId} @ ${span(i.location)}: ${i.expected}\n  check: ${i.howToCheck}${i.familyId ? ` (family ${i.familyId})` : ''}`,
        )
        .join('\n')}`,
    );
  }
  if (sections.has('baselines') && gt.baselines.length) {
    blocks.push(
      `### Baseline-correct references (${gt.baselines.length}; diff every sibling against these)\n${gt.baselines
        .map((b) => `- ${b.baselineId} ${b.pattern} @ ${span(b.location)}: ${b.whyCorrect}`)
        .join('\n')}`,
    );
  }
  if (sections.has('families') && gt.families.length) {
    blocks.push(
      `### Variant families (${gt.families.length}; one hunt-log row per member)\n${gt.families
        .map(
          (f) =>
            `- ${f.familyId} ${f.rootCause}${f.baselineId ? ` (baseline ${f.baselineId})` : ''}\n${f.members
              .map((m) => `  - ${m.path}:${m.startLine} ${m.label}`)
              .join('\n')}`,
        )
        .join('\n')}`,
    );
  }
  if (sections.has('carveouts') && gt.carveouts.length) {
    blocks.push(
      `### False-positive carve-outs (${gt.carveouts.length}; do not report unless the justification fails)\n${gt.carveouts
        .map(
          (c) =>
            `- ${c.carveoutId} [${c.source}] ${c.pattern}: ${c.justification}${c.evidence.length ? ` (${c.evidence.map(span).join(', ')})` : ''}`,
        )
        .join('\n')}`,
    );
  }
  if (sections.has('unknowns') && gt.residualUnknowns.length) {
    blocks.push(
      `### Residual unknowns (${gt.residualUnknowns.length}; carry into preconditions, do not assume)\n${gt.residualUnknowns
        .map((u) => `- ${u.unknownId} [${u.kind}] ${u.question} — ${u.whySourceCannotSettle}`)
        .join('\n')}`,
    );
  }
  let body = blocks.join('\n\n');
  if (body.length > maxChars) body = `${body.slice(0, maxChars - 40)}\n… (ground truth truncated)`;
  return `<ground_truth untrusted="true" source="recon">\n${body}\n</ground_truth>`;
}

/** Host-side checks of the recon deliverable: every cited line exists, ids are unique and resolvable. */
export async function validateGroundTruth(
  gt: GroundTruth,
  ctx: Pick<CodeToolContext, 'source' | 'paths'>,
  options: { packetIds?: ReadonlySet<string> } = {},
): Promise<string[]> {
  const problems: string[] = [];
  const citations = [
    ...gt.invariants.map((i) => i.location),
    ...gt.baselines.map((b) => b.location),
    ...gt.families.flatMap((f) =>
      f.members.map((m) => ({ path: m.path, startLine: m.startLine, endLine: m.startLine })),
    ),
    ...gt.carveouts.flatMap((c) => c.evidence),
  ];
  problems.push(...(await checkCitations(ctx, citations)).map((p) => `ground truth ${p}`));
  const dupes = (ids: string[], what: string) => {
    const seen = new Set<string>();
    for (const id of ids) {
      if (seen.has(id)) problems.push(`duplicate ${what} id ${id}`);
      seen.add(id);
    }
  };
  dupes(
    gt.invariants.map((i) => i.invariantId),
    'invariant',
  );
  dupes(
    gt.baselines.map((b) => b.baselineId),
    'baseline',
  );
  dupes(
    gt.families.map((f) => f.familyId),
    'family',
  );
  dupes(
    gt.carveouts.map((c) => c.carveoutId),
    'carve-out',
  );
  dupes(
    gt.residualUnknowns.map((u) => u.unknownId),
    'unknown',
  );
  const baselineIds = new Set(gt.baselines.map((b) => b.baselineId));
  const familyIds = new Set(gt.families.map((f) => f.familyId));
  for (const f of gt.families) {
    if (f.baselineId && !baselineIds.has(f.baselineId))
      problems.push(`${f.familyId} references missing ${f.baselineId}`);
  }
  for (const i of gt.invariants) {
    if (i.familyId && !familyIds.has(i.familyId)) problems.push(`${i.invariantId} references missing ${i.familyId}`);
    if (options.packetIds) {
      for (const p of i.packets)
        if (!options.packetIds.has(p)) problems.push(`${i.invariantId} names unknown packet ${p}`);
    }
  }
  for (const c of gt.carveouts) {
    if (c.source === 'recon' && c.evidence.length === 0)
      problems.push(`${c.carveoutId} needs at least one evidence location (a carve-out is a claim about this code)`);
  }
  return problems;
}

export interface ClosedEndedResult {
  findings: readonly AiFinding[];
  invariantResults: readonly InvariantResult[];
  variantLog: readonly VariantHuntRow[];
  deferred: readonly string[];
}

const primaryOf = (f: AiFinding) => f.locations.find((l) => l.role === 'primary') ?? f.locations[0];
const near = (a: number, b: number, tolerance: number) => Math.abs(a - b) <= tolerance;

/**
 * Closed-ended coverage checks (ADR-049), returned to the model as submission problems: a FAIL
 * without a finding, a VULNERABLE member without a finding, an UNKNOWN without a note, a by-design
 * item filed as a finding, a HIGH-confidence finding with open proof obligations, and references
 * to ids outside the slice. Missing checklist rows are problems only in `strict` mode; otherwise
 * they are coverage gaps the host records.
 */
export function closedEndedProblems(
  result: ClosedEndedResult,
  slice: GroundTruth,
  options: { strict?: boolean } = {},
): string[] {
  const problems: string[] = [];
  const invariantIds = new Set(slice.invariants.map((i) => i.invariantId));
  const familyIds = new Set(slice.families.map((f) => f.familyId));
  const baselineIds = new Set(slice.baselines.map((b) => b.baselineId));
  const deferredText = result.deferred.join('\n');
  const findingsByInvariant = new Set(result.findings.map((f) => f.invariantId).filter(Boolean));
  for (const r of result.invariantResults) {
    if (!invariantIds.has(r.invariantId))
      problems.push(`invariantResults names ${r.invariantId}, which is not in your slice`);
    if (r.result === 'FAIL' && !findingsByInvariant.has(r.invariantId) && !deferredText.includes(r.invariantId)) {
      problems.push(
        `${r.invariantId} is FAIL but no finding carries invariantId ${r.invariantId} (report it, or defer it by id)`,
      );
    }
    if (r.result === 'UNKNOWN' && !r.note.trim())
      problems.push(`${r.invariantId} is UNKNOWN without a note saying what is missing`);
  }
  for (const row of result.variantLog) {
    if (!familyIds.has(row.familyId)) problems.push(`variantLog names ${row.familyId}, which is not in your slice`);
    if (row.verdict === 'VULNERABLE') {
      const covered = result.findings.some((f) => {
        const p = primaryOf(f);
        return p !== undefined && p.path === row.member.path && near(p.startLine, row.member.startLine, 3);
      });
      if (!covered && !deferredText.includes(`${row.member.path}:${row.member.startLine}`)) {
        problems.push(
          `${row.familyId} member ${row.member.path}:${row.member.startLine} is VULNERABLE but no finding has a primary location there`,
        );
      }
    }
  }
  for (const f of result.findings) {
    if (f.threatModelClass === 'by_design') problems.push(`"${f.title}" is by_design: move it to notes, not findings`);
    if (f.confidence === 'HIGH' && f.proofObligations.length > 0)
      problems.push(
        `"${f.title}" has HIGH confidence but open proof obligations (${f.proofObligations.length}); lower the confidence or prove them`,
      );
    if (f.invariantId && !invariantIds.has(f.invariantId))
      problems.push(`"${f.title}" references ${f.invariantId} outside your slice`);
    if (f.familyId && !familyIds.has(f.familyId))
      problems.push(`"${f.title}" references ${f.familyId} outside your slice`);
    if (f.baselineReference && !baselineIds.has(f.baselineReference))
      problems.push(`"${f.title}" references ${f.baselineReference} outside your slice`);
  }
  if (options.strict) {
    const seen = new Set(result.invariantResults.map((r) => r.invariantId));
    for (const id of invariantIds)
      if (!seen.has(id)) problems.push(`${id} has no result; report PASS, FAIL or UNKNOWN`);
  }
  return problems;
}

/** Coverage of a ground truth by the results collected so far (objectives INVARIANTS_CHECKED / FAMILIES_SWEPT). */
export function coverageOf(
  gt: GroundTruth,
  results: ReadonlyArray<Pick<ClosedEndedResult, 'invariantResults' | 'variantLog'>>,
): GroundTruthCoverage {
  const checked = new Set(results.flatMap((r) => r.invariantResults.map((i) => i.invariantId)));
  const swept = new Set(
    results.flatMap((r) => r.variantLog.map((v) => `${v.familyId} ${v.member.path}:${v.member.startLine}`)),
  );
  const members = gt.families.flatMap((f) => f.members.map((m) => `${f.familyId} ${m.path}:${m.startLine}`));
  return {
    invariantGaps: gt.invariants.map((i) => i.invariantId).filter((id) => !checked.has(id)),
    invariantTotal: gt.invariants.length,
    memberGaps: members.filter((m) => !swept.has(m)),
    memberTotal: members.length,
  };
}

/** Stable key of a finding for critic dedupe: normalized title plus primary location bucket. */
export function findingKey(f: Pick<AiFinding, 'title' | 'category' | 'locations'>): string {
  const p = primaryOf(f as AiFinding);
  return `${f.category}::${f.title.trim().toLowerCase().replace(/\s+/g, ' ')}::${p?.path ?? ''}:${Math.round((p?.startLine ?? 0) / 3)}`;
}

/** Two findings describe the same issue when they share a category and overlapping primary lines. */
export function isDuplicate(
  a: Pick<AiFinding, 'title' | 'category' | 'locations'>,
  b: Pick<AiFinding, 'title' | 'category' | 'locations'>,
): boolean {
  if (a.category !== b.category) return false;
  const pa = primaryOf(a as AiFinding);
  const pb = primaryOf(b as AiFinding);
  if (!pa || !pb || pa.path !== pb.path) return false;
  return pa.startLine <= pb.endLine + 2 && pa.endLine + 2 >= pb.startLine;
}

/** Operator context (ADR-051) folded into the ground truth: accepted risks become operator carve-outs, claims become trust claims. */
export function mergeOperatorContext(gt: GroundTruth, ctx: AiContextConfig | undefined): GroundTruth {
  if (!ctx) return gt;
  const carveouts: Carveout[] = ctx.accepted_risks.map((risk, i) => ({
    carveoutId: `CO-${900 + i}`,
    pattern: risk.slice(0, 300),
    justification: 'Declared by the operator as accepted or intended behaviour (ai.context.accepted_risks).',
    evidence: [],
    source: 'operator' as const,
  }));
  const claims = [
    ...ctx.trust_claims.map((c) => ({
      statement: c.statement,
      provenance: c.provenance,
      confidence: 'claimed' as const,
    })),
    ...ctx.business_invariants.map((c) => ({
      statement: `Business invariant: ${c.statement}`,
      provenance: c.provenance,
      confidence: 'claimed' as const,
    })),
    ...ctx.roles.map((r) => ({
      statement: `Role ${r.name}: ${r.trust}`,
      provenance: r.provenance,
      confidence: 'claimed' as const,
    })),
  ];
  return {
    ...gt,
    carveouts: [...gt.carveouts, ...carveouts].slice(0, 20),
    trustClaims: [...gt.trustClaims, ...claims].slice(0, 30),
  };
}

/** Operator context for prompts: claimed, with provenance, never proof. */
export function renderOperatorContext(ctx: AiContextConfig | undefined): string {
  if (!ctx) return '';
  const lines: string[] = [];
  for (const r of ctx.roles) lines.push(`- role ${r.name}: ${r.trust} (${r.provenance})`);
  for (const c of ctx.trust_claims) lines.push(`- ${c.statement} (${c.provenance})`);
  for (const c of ctx.business_invariants) lines.push(`- business invariant: ${c.statement} (${c.provenance})`);
  for (const r of ctx.accepted_risks) lines.push(`- accepted risk: ${r}`);
  if (!lines.length) return '';
  return `<operator_context untrusted="false" confidence="claimed">\nStatements supplied by the operator about deployment, roles and business rules. They are claims with provenance, not source evidence: use them to avoid reporting intended behaviour, and recheck any that a finding depends on.\n${lines.join('\n')}\n</operator_context>`;
}

/** Text for the `{{accepted_risks}}` slot of the design-context partial. */
export function acceptedRisksVar(ctx: AiContextConfig | undefined): string {
  return ctx?.accepted_risks.length ? ctx.accepted_risks.map((r) => `"${r}"`).join('; ') : 'none declared.';
}
