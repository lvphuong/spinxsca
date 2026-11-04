import { z } from 'zod';
import { Severity } from './common';
import { Category, CweId } from './taxonomy';

export const DetectionLayer = z.enum(['sast', 'sca', 'secrets', 'iac', 'ai']);
export type DetectionLayer = z.infer<typeof DetectionLayer>;

const LineRange = z.tuple([z.number().int().positive(), z.number().int().positive()]);

/** Ground truth for one evaluation case (evals/<suite>/<case>/case.yaml). */
export const EvalCase = z.strictObject({
  id: z.string(),
  title: z.string(),
  description: z.string().optional(),
  languages: z.array(z.string()).min(1),
  /** Source root inside the case directory. */
  source: z.string().default('src'),
  findings: z
    .array(
      z.strictObject({
        id: z.string(),
        category: Category,
        cwe: z.array(CweId).min(1),
        path: z.string(),
        lines: LineRange,
        severity: Severity.optional(),
        detectable_by: z.array(DetectionLayer).min(1),
        /** Roadmap phase in which spinxsca is expected to detect this finding. */
        min_phase: z.number().int().nonnegative().default(0),
        /** For dependency findings: the advisory that must be reported (any alias matches). */
        vulnerability_id: z.string().optional(),
        notes: z.string().optional(),
      }),
    )
    .default([]),
  /** Regions where any reported finding is a false positive. */
  negatives: z
    .array(
      z.strictObject({
        path: z.string(),
        lines: LineRange.optional(),
        reason: z.string(),
      }),
    )
    .default([]),
});
export type EvalCase = z.infer<typeof EvalCase>;

export const EvalThresholds = z.strictObject({
  phase: z.number().int().nonnegative(),
  precision_min: z.number().min(0).max(1),
  recall_min: z.number().min(0).max(1),
  identity_stability_min: z.number().min(0).max(1),
});
export type EvalThresholds = z.infer<typeof EvalThresholds>;

/** Autonomous review evaluation case (evals/ai, Phase 5). */
export const AiEvalCase = z.strictObject({
  id: z.string(),
  title: z.string(),
  description: z.string().optional(),
  source: z.string().default('src'),
  /** Vulnerable/fixed pairs share a pair name. */
  pair: z.string().optional(),
  variant: z.enum(['vulnerable', 'fixed']).optional(),
  /** Allow sandboxed proofs of concept without asking (operator setting of the eval run). */
  l3: z.boolean().default(false),
  /** Commits created before the source is copied in (history secrets). */
  git_history: z.array(z.strictObject({ message: z.string(), files: z.record(z.string(), z.string()) })).default([]),
  /** Values that must never appear in requests, the case store, artifacts or reports. */
  secrets: z.array(z.string().min(8)).default([]),
  expect: z
    .strictObject({
      findings: z
        .array(
          z.strictObject({
            id: z.string(),
            category: Category,
            path: z.string(),
            lines: LineRange.optional(),
            scanner: z.string().optional(),
            vulnerability_id: z.string().optional(),
            classification: z.enum(['CONFIRMED', 'POTENTIAL', 'UNLIKELY']).optional(),
            applicability: z.enum(['AFFECTED', 'NOT_AFFECTED', 'UNDER_INVESTIGATION']).optional(),
            reachability: z.string().optional(),
            poc: z.enum(['CONFIRMED', 'NOT_CONFIRMED']).optional(),
            max_severity: Severity.optional(),
          }),
        )
        .default([]),
      no_confirmed_poc: z.boolean().default(false),
      side_effects: z.enum(['none', 'any']).default('any'),
    })
    .default({ findings: [], no_confirmed_poc: false, side_effects: 'any' }),
});
export type AiEvalCase = z.infer<typeof AiEvalCase>;
