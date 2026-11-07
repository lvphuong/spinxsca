import { z } from 'zod';
import { Digest } from './common';

/**
 * Hierarchical repository digest (ADR-056): deterministic per-directory summaries small enough to
 * sit in a recon or mapper prompt, with a `repo_map` tool to drill down. Numbers come from the
 * snapshot, the code index and the census; the optional one-line summary may come from a model.
 */
export const DigestNode = z.strictObject({
  path: z.string(),
  kind: z.enum(['dir', 'file']),
  files: z.number().int().nonnegative(),
  loc: z.number().int().nonnegative(),
  bytes: z.number().int().nonnegative(),
  /** Files per language (by extension). */
  languages: z.record(z.string(), z.number().int().nonnegative()),
  endpoints: z.number().int().nonnegative(),
  controls: z.number().int().nonnegative(),
  dataAccess: z.number().int().nonnegative(),
  symbols: z.number().int().nonnegative(),
  /** Most frequent external packages imported under this node. */
  externalImports: z.array(z.string()).max(12),
  topEndpoints: z.array(z.string()).max(6),
  summary: z.string().max(400).optional(),
  children: z.array(z.string()),
});
export type DigestNode = z.infer<typeof DigestNode>;

export const RepoDigest = z.strictObject({
  version: z.literal(1),
  contentManifestDigest: Digest,
  root: z.string(),
  nodes: z.record(z.string(), DigestNode),
  stats: z.strictObject({
    files: z.number().int().nonnegative(),
    loc: z.number().int().nonnegative(),
    directories: z.number().int().nonnegative(),
    endpoints: z.number().int().nonnegative(),
  }),
});
export type RepoDigest = z.infer<typeof RepoDigest>;
