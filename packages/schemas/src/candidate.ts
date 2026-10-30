import { z } from 'zod';
import { Confidence, FingerprintAnchor, Location, PackageRef, Severity } from './common';
import { Category, CweId } from './taxonomy';

/**
 * Normalized scanner output. Immutable once written; the reconciliation step decides how it maps
 * onto finding identities.
 */
export const FindingCandidate = z.object({
  candidateId: z.string(),
  scanId: z.string(),
  scanTaskId: z.string(),
  scanner: z.string(),
  ruleId: z.string(),
  /** Groups equivalent rules across scanners (e.g. semgrep and codeql SQL injection rules). */
  ruleFamily: z.string(),
  category: Category,
  cwe: z.array(CweId),
  title: z.string(),
  message: z.string(),
  severityHint: Severity,
  confidenceHint: Confidence,
  locations: z.array(Location).min(1),
  package: PackageRef.optional(),
  vulnerabilityIds: z.array(z.string()).optional(),
  fingerprints: z.object({
    scanner: z.string().optional(),
    /** spinxsca/fp/v1, computed by the host. */
    semantic: z.string(),
    algorithm: z.string(),
    anchor: FingerprintAnchor,
  }),
  evidenceIds: z.array(z.string()),
});
export type FindingCandidate = z.infer<typeof FindingCandidate>;
