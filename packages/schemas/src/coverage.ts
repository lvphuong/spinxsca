import { z } from 'zod';
import { Digest } from './common';

export const Completeness = z.enum(['COMPLETE', 'PARTIAL', 'FAILED']);
export type Completeness = z.infer<typeof Completeness>;

/**
 * Required for every scan task and agent run (ADR-006). A finding may only be marked resolved when
 * coverage proves the relevant file and rule were analysed by a complete task.
 */
export const Coverage = z.object({
  scope: z.enum(['FULL', 'INCREMENTAL', 'TARGETED']),
  completeness: Completeness,
  files: z.object({
    analyzed: z.number().int().nonnegative(),
    total: z.number().int().nonnegative(),
    /** Artifact holding the JSON array of analysed repository-relative paths. */
    listDigest: Digest.optional(),
  }),
  languages: z.array(z.string()),
  rules: z
    .object({
      executed: z.number().int().nonnegative(),
      bundleDigests: z.array(Digest),
      /** Rule ids that were part of the executed bundles. */
      ids: z.array(z.string()),
    })
    .optional(),
  /** Semantic coverage for AI runs (codex-security coverage.schema.json). */
  reviewedSurfaces: z.array(z.string()).optional(),
  deferred: z.array(z.object({ candidateId: z.string(), reason: z.string() })).optional(),
  rejected: z.array(z.object({ candidateId: z.string(), counterevidence: z.string() })).optional(),
  exclusions: z.array(z.string()).optional(),
  toolErrors: z.array(z.object({ tool: z.string(), message: z.string(), path: z.string().optional() })),
});
export type Coverage = z.infer<typeof Coverage>;
