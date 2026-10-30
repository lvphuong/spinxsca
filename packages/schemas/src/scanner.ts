import { z } from 'zod';
import { Digest } from './common';

export const ScannerCapabilityKind = z.enum(['SAST', 'SCA', 'SECRETS', 'IAC']);

export const ScannerCapability = z.object({
  id: z.string(),
  adapterVersion: z.string(),
  toolVersion: z.string(),
  /** Container image reference pinned by digest: "<name>@sha256:<hex>". */
  image: z.string(),
  capabilities: z.array(ScannerCapabilityKind),
  languages: z.array(z.string()),
  scanModes: z.array(z.enum(['FULL', 'INCREMENTAL', 'TARGETED'])),
  outputs: z.array(z.enum(['SARIF', 'NATIVE_JSON'])),
  requiresNetwork: z.boolean(),
  requiresBuild: z.boolean(),
  resources: z.object({
    cpus: z.number().positive(),
    memoryMb: z.number().int().positive(),
    timeoutSec: z.number().int().positive(),
  }),
});
export type ScannerCapability = z.infer<typeof ScannerCapability>;

export const RuleBundleRef = z.object({
  id: z.string(),
  version: z.string(),
  digest: Digest,
  ruleCount: z.number().int().nonnegative(),
});
export type RuleBundleRef = z.infer<typeof RuleBundleRef>;
