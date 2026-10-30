import { z } from 'zod';
import { Digest, Location } from './common';

export const EvidenceKind = z.enum([
  'CODE_SNIPPET',
  'DATAFLOW_PATH',
  'CALL_PATH',
  'ENDPOINT_CONTEXT',
  'AUTH_CONTEXT',
  'SCANNER_RESULT',
  'PACKAGE_MATCH',
  'KB_RECORD',
  'SANDBOX_RUN',
  'TOOL_OUTPUT',
]);
export type EvidenceKind = z.infer<typeof EvidenceKind>;

/** Evidence is content-addressed and referenced by id from candidates, occurrences and assessments. */
export const Evidence = z.object({
  evidenceId: z.string(),
  kind: EvidenceKind,
  producedBy: z.string(),
  snapshotId: z.string(),
  locations: z.array(Location).default([]),
  /** Small inline excerpt (for example up to 40 lines of code). Secrets must already be redacted. */
  excerpt: z.string().optional(),
  payloadDigest: Digest.optional(),
  summary: z.string(),
});
export type Evidence = z.infer<typeof Evidence>;
