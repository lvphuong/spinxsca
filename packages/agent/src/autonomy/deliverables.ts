import type { DependencyPort, SourceTree, ValidationPort } from '@spinxsca/core';
import { AiFinding, Confidence, Severity, SourceRef, type WorkItemKind } from '@spinxsca/schemas';
import { z } from 'zod';
import type { SubmitTool } from '../runtime/tools';
import { checkCitations } from '../tools/code-tools';

const handle = z.string().regex(/^CF-\d+$/);
const Evidence = SourceRef.extend({ note: z.string().max(600).optional() });

export const TriageDeliverable = z.strictObject({
  handle,
  verdict: z
    .enum(['TRUE_POSITIVE', 'FALSE_POSITIVE', 'BLOCKED'])
    .describe(
      'TRUE_POSITIVE: evidence shows the issue is real here. FALSE_POSITIVE: source-backed counterevidence. BLOCKED: you could not decide; say what is missing.',
    ),
  severity: Severity.describe('Exposure in this codebase under the rubric, not the generic rule severity'),
  confidence: Confidence,
  rationale: z.string().min(20).max(3000),
  evidence: z.array(Evidence).max(10).describe('Code locations that support the verdict'),
  counterevidence: z.array(z.string().max(600)).max(8),
  noiseReason: z
    .string()
    .max(600)
    .optional()
    .describe('FALSE_POSITIVE only: why the tool fired (constant input, test code, sanitized, dead code, ...)'),
  attackPath: z
    .strictObject({
      attacker: z.string().max(300),
      entryPoint: z.string().max(300),
      source: z.string().max(300),
      sink: z.string().max(300),
      preconditions: z.array(z.string().max(300)).max(8),
      controls: z.array(z.string().max(300)).max(8),
    })
    .optional(),
  missingEvidence: z.array(z.string().max(600)).max(8).default([]),
});
export type TriageDeliverable = z.infer<typeof TriageDeliverable>;

export const ApplicabilityDeliverable = z.strictObject({
  handle,
  status: z.enum(['AFFECTED', 'NOT_AFFECTED', 'UNDER_INVESTIGATION']),
  justification: z
    .enum([
      'component_not_present',
      'vulnerable_code_not_present',
      'vulnerable_code_not_in_execute_path',
      'vulnerable_code_cannot_be_controlled_by_adversary',
      'inline_mitigations_already_exist',
    ])
    .optional()
    .describe('Required for NOT_AFFECTED (CISA VEX justification)'),
  vulnerableSymbols: z.array(z.string().max(120)).max(20).describe('Functions the advisory says are vulnerable'),
  symbolSource: z.enum(['advisory', 'model', 'none']),
  severity: Severity,
  confidence: Confidence,
  rationale: z.string().min(20).max(3000),
  evidence: z.array(Evidence).max(10),
});
export type ApplicabilityDeliverable = z.infer<typeof ApplicabilityDeliverable>;

export const FindingsDeliverable = z.strictObject({
  findings: z.array(AiFinding).max(12),
  notes: z.string().max(3000),
  deferred: z.array(z.string().max(300)).max(10).describe('Checks you could not finish'),
});
export type FindingsDeliverable = z.infer<typeof FindingsDeliverable>;

export const PocDeliverable = z.strictObject({
  handle,
  workspaceId: z.string().regex(/^ws-[a-z0-9-]+$/),
  oracle: z.enum(['CANARY_READ', 'COMMAND_MARKER', 'DATA_DIFFERENTIAL', 'UNESCAPED_REFLECTION']),
  summary: z
    .string()
    .min(10)
    .max(2000)
    .describe('What the harness does and why the attack input reaches the vulnerable code'),
});
export type PocDeliverable = z.infer<typeof PocDeliverable>;

export const PocReviewDeliverable = z.strictObject({
  handle,
  approve: z
    .boolean()
    .describe('True only if the harness reaches the marker through the vulnerable code, not by itself'),
  reason: z.string().min(10).max(2000),
  concerns: z.array(z.string().max(400)).max(8),
});
export type PocReviewDeliverable = z.infer<typeof PocReviewDeliverable>;

export const PlanDeliverable = z.strictObject({
  notes: z.string().max(3000),
  done: z.boolean().describe('True when nothing more is worth planning this round'),
});

export interface DeliverableContext {
  source: SourceTree;
  paths: readonly string[];
  dependencies?: DependencyPort;
  /** Package of a dependency handle (for the reachability cross-check). */
  packageOf?: (handle: string) => { ecosystem: string; name: string } | undefined;
  validation?: ValidationPort;
}

/** Submit tool of a work item kind, with host-side checks returned to the model as problems. */
export function submitFor(kind: WorkItemKind, ctx: DeliverableContext): SubmitTool<unknown> | undefined {
  switch (kind) {
    case 'TRIAGE_FINDING':
      return {
        name: 'submit_triage',
        description: 'Submit your verdict for the finding with evidence.',
        output: TriageDeliverable,
        validate: (o) => triageProblems(o as TriageDeliverable, ctx),
      } as SubmitTool<unknown>;
    case 'DEPENDENCY_APPLICABILITY':
      return {
        name: 'submit_applicability',
        description: 'Submit whether the vulnerable dependency affects this project (VEX).',
        output: ApplicabilityDeliverable,
        validate: (o) => applicabilityProblems(o as ApplicabilityDeliverable, ctx),
      } as SubmitTool<unknown>;
    case 'THREAT_PACKET':
    case 'BASELINE_AUDIT':
    case 'HYPOTHESIS':
    case 'VARIANT_HUNT':
    case 'SECRETS_SWEEP':
    case 'IAC_REVIEW':
      return {
        name: 'submit_findings',
        description: 'Submit new findings (each needs a primary location and evidence) and what you could not finish.',
        output: FindingsDeliverable,
        validate: (o) =>
          checkCitations(
            ctx,
            (o as FindingsDeliverable).findings.flatMap((f) => f.locations),
          ),
      } as SubmitTool<unknown>;
    case 'EXPLOIT_POC':
      return {
        name: 'submit_poc',
        description: 'Submit after validation_run, whatever the host decided.',
        output: PocDeliverable,
        validate: async (o) => {
          const d = o as PocDeliverable;
          const run = await ctx.validation?.lastRun(d.workspaceId, d.handle);
          return run ? [] : [`no validation_run for ${d.handle} in ${d.workspaceId} yet: run the harness first`];
        },
      } as SubmitTool<unknown>;
    case 'REVIEW_POC':
      return {
        name: 'submit_poc_review',
        description: 'Approve or reject the PoC harness.',
        output: PocReviewDeliverable,
      } as SubmitTool<unknown>;
    default:
      return undefined;
  }
}

export async function triageProblems(o: TriageDeliverable, ctx: DeliverableContext): Promise<string[]> {
  const problems = await checkCitations(ctx, o.evidence);
  if (o.verdict === 'TRUE_POSITIVE' && o.evidence.length === 0)
    problems.push('a TRUE_POSITIVE needs at least one evidence location');
  if (o.verdict === 'TRUE_POSITIVE' && ['CRITICAL', 'HIGH'].includes(o.severity) && !o.attackPath) {
    problems.push('HIGH and CRITICAL findings need an attackPath (attacker, entry point, source, sink, controls)');
  }
  if (o.verdict === 'FALSE_POSITIVE') {
    if (o.counterevidence.length === 0) problems.push('a FALSE_POSITIVE needs source-backed counterevidence');
    if (!o.noiseReason) problems.push('a FALSE_POSITIVE needs noiseReason: why the tool fired');
  }
  if (o.verdict === 'BLOCKED' && o.missingEvidence.length === 0)
    problems.push('BLOCKED needs missingEvidence: what would decide it');
  return problems;
}

/** NOT_AFFECTED is refused while the index shows the vulnerable code called from an entry point. */
export async function applicabilityProblems(o: ApplicabilityDeliverable, ctx: DeliverableContext): Promise<string[]> {
  const problems = await checkCitations(ctx, o.evidence);
  if (o.status === 'NOT_AFFECTED' && !o.justification) problems.push('NOT_AFFECTED needs a VEX justification');
  const pkg = ctx.packageOf?.(o.handle);
  if (o.status === 'NOT_AFFECTED' && pkg && ctx.dependencies) {
    const usage = await ctx.dependencies.reachability({
      ...pkg,
      ...(o.vulnerableSymbols.length ? { symbols: o.vulnerableSymbols } : {}),
      ...(o.symbolSource !== 'none' ? { symbolSource: o.symbolSource } : {}),
    });
    const overridable =
      o.justification === 'inline_mitigations_already_exist' ||
      o.justification === 'vulnerable_code_cannot_be_controlled_by_adversary';
    if (usage.level === 'CALLED_FROM_ENTRYPOINT' && !(overridable && o.evidence.length > 0)) {
      problems.push(
        `the index shows ${pkg.name} called from ${usage.entrypoints.map((e) => `${e.method} ${e.route}`).join(', ')}; NOT_AFFECTED needs a mitigation or adversary-control justification with evidence`,
      );
    }
    if (
      (usage.level === 'CALLED' || usage.level === 'CALLED_FROM_ENTRYPOINT') &&
      o.justification === 'vulnerable_code_not_in_execute_path' &&
      !o.vulnerableSymbols.length
    ) {
      problems.push(
        `the package is called (${usage.callSites.length} call sites); name the vulnerable symbols to argue they are not used`,
      );
    }
  }
  return problems;
}
