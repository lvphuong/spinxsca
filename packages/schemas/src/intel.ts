import { z } from 'zod';

/**
 * Exploitation and scoring intelligence for a dependency advisory (docs/architecture/04 section 5):
 * CISA KEV, FIRST EPSS and NVD CVSS, resolved through the advisory's CVE aliases. Shown side by side,
 * never merged into one score; triage order is KEV, then EPSS, then CVSS.
 */
export const VulnIntel = z.object({
  cves: z.array(z.string()),
  kev: z
    .object({
      dateAdded: z.string(),
      dueDate: z.string().optional(),
      ransomware: z.boolean(),
      catalogVersion: z.string(),
    })
    .optional(),
  epss: z.object({ score: z.number(), percentile: z.number(), date: z.string() }).optional(),
  cvss: z.object({ version: z.string(), baseScore: z.number(), vector: z.string(), source: z.string() }).optional(),
  cwes: z.array(z.string()).optional(),
});
export type VulnIntel = z.infer<typeof VulnIntel>;
