import { z } from 'zod';
import { Digest, Timestamp } from './common';
import { RuleBundleRef } from './scanner';

export const ScanMode = z.enum([
  'FULL',
  'INCREMENTAL',
  'QUICK',
  'TARGETED',
  'DEPENDENCY_REASSESSMENT',
  'RULE_REASSESSMENT',
  'FINDING_VERIFICATION',
  'AI_REANALYSIS',
]);
export type ScanMode = z.infer<typeof ScanMode>;

export const AiLevel = z.enum(['off', 'explain', 'standard', 'deep']);
export type AiLevel = z.infer<typeof AiLevel>;

/**
 * Frozen before the first task runs (ADR-003). Five independently versioned inputs: source,
 * scanner bundle, rule bundle, knowledge base snapshot and AI policy.
 */
export const AnalysisManifest = z.object({
  schemaVersion: z.literal(1),
  scanId: z.string(),
  engineVersion: z.string(),
  source: z.object({
    snapshotId: z.string(),
    contentManifestDigest: Digest,
    commitSha: z.string().optional(),
    /** Branch the scan is attributed to (explicit for server checkouts, else the git branch at capture). */
    branch: z.string().optional(),
  }),
  scannerBundle: z.object({
    digest: Digest,
    scanners: z.array(
      z.object({
        id: z.string(),
        adapterVersion: z.string(),
        toolVersion: z.string(),
        image: z.string(),
      }),
    ),
  }),
  ruleBundles: z.array(RuleBundleRef),
  /** Knowledge base snapshot used by dependency scanners; null when no SCA scanner ran. */
  knowledgeBase: z
    .object({
      snapshotId: z.string(),
      digest: Digest,
      /** Ecosystems whose advisories are fully mirrored in the snapshot. */
      ecosystems: z.array(z.string()).default([]),
    })
    .nullable(),
  aiPolicy: z.object({
    level: AiLevel,
    policyVersion: z.string(),
    promptBundleDigest: Digest.optional(),
    provider: z.string().optional(),
    model: z.string().optional(),
  }),
  scanMode: ScanMode,
  baselineScanId: z.string().optional(),
  scope: z.object({
    exclude: z.array(z.string()),
  }),
  requestedAt: Timestamp,
});
export type AnalysisManifest = z.infer<typeof AnalysisManifest>;
