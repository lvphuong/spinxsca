import { z } from 'zod';

export const Severity = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
export type Severity = z.infer<typeof Severity>;

/** Higher number = more severe. Used for sorting and policy thresholds. */
export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

export function severityAtLeast(value: Severity, threshold: Severity): boolean {
  return SEVERITY_RANK[value] >= SEVERITY_RANK[threshold];
}

/** Calibrated buckets only; numeric probabilities are not used until evals calibrate them. */
export const Confidence = z.enum(['HIGH', 'MEDIUM', 'LOW']);
export type Confidence = z.infer<typeof Confidence>;

export const Timestamp = z.iso.datetime();

/** sha256 digest in the form "sha256:<64 hex>". */
export const Digest = z.string().regex(/^sha256:[0-9a-f]{64}$/, 'expected sha256:<hex>');
export type Digest = z.infer<typeof Digest>;

export const LocationRole = z.enum(['primary', 'source', 'sink', 'guard', 'related']);
export type LocationRole = z.infer<typeof LocationRole>;

export const Location = z.object({
  /** Repository-relative POSIX path. */
  path: z.string().min(1),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
  startColumn: z.number().int().positive().optional(),
  endColumn: z.number().int().positive().optional(),
  /** Stable symbol identity when known (code-intel), or a heuristic key prefixed with "heuristic:". */
  symbolKey: z.string().optional(),
  role: LocationRole.default('primary'),
});
export type Location = z.infer<typeof Location>;

export const PackageRef = z.object({
  purl: z.string(),
  ecosystem: z.string(),
  name: z.string(),
  version: z.string(),
  manifestPath: z.string(),
  direct: z.boolean().optional(),
});
export type PackageRef = z.infer<typeof PackageRef>;

export const ArtifactRef = z.object({
  digest: Digest,
  mediaType: z.string(),
  size: z.number().int().nonnegative(),
});
export type ArtifactRef = z.infer<typeof ArtifactRef>;

/**
 * Path-independent and path-dependent parts of a semantic fingerprint, kept so reconciliation can
 * match a finding after a file rename (same symbol + shape) or a small edit (same path + symbol).
 */
export const FingerprintAnchor = z.object({
  path: z.string(),
  symbol: z.string(),
  shape: z.string(),
  instance: z.number().int().nonnegative(),
});
export type FingerprintAnchor = z.infer<typeof FingerprintAnchor>;
