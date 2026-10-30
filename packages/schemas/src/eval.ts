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
