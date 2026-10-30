import { z } from 'zod';
import { Digest, Timestamp } from './common';

export const SnapshotKind = z.enum(['GIT_COMMIT', 'WORKSPACE']);
export type SnapshotKind = z.infer<typeof SnapshotKind>;

/**
 * Immutable source state (ADR-002). A dirty git working tree is captured as WORKSPACE so results
 * are never attributed to HEAD.
 */
export const SourceSnapshot = z.object({
  snapshotId: z.string(),
  repositoryId: z.string(),
  kind: SnapshotKind,
  commitSha: z.string().optional(),
  treeSha: z.string().optional(),
  branchAtCapture: z.string().optional(),
  /** sha256 over the sorted list of (path, blob digest). */
  contentManifestDigest: Digest,
  fileCount: z.number().int().nonnegative(),
  /** Artifact holding the JSON file list [{ path, digest, size }]. */
  fileListDigest: Digest,
  capturedAt: Timestamp,
});
export type SourceSnapshot = z.infer<typeof SourceSnapshot>;

export const SnapshotFile = z.object({
  path: z.string(),
  digest: Digest,
  size: z.number().int().nonnegative(),
});
export type SnapshotFile = z.infer<typeof SnapshotFile>;
