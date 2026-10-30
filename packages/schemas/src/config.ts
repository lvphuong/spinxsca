import { z } from 'zod';
import type { Severity } from './common';

const LowerSeverity = z
  .enum(['critical', 'high', 'medium', 'low', 'info'])
  .transform((value) => value.toUpperCase() as Severity);

const Toggle = z.strictObject({ enabled: z.boolean().default(true) });

/**
 * spinxsca.yaml. Closed schema: unknown keys are errors (docs/architecture/05 section 3). The file is
 * operator configuration and is never auto-discovered from the scanned repository (ADR-025).
 */
export const SpinxscaConfig = z.strictObject({
  version: z.literal(1),
  project: z.strictObject({ name: z.string().min(1).optional() }).optional(),
  scan: z
    .strictObject({
      exclude: z.array(z.string()).default([]),
      scanners: z
        .strictObject({
          semgrep: z
            .strictObject({
              enabled: z.boolean().default(true),
              /** Extra local rule directories, relative to the config file. */
              rule_dirs: z.array(z.string()).default([]),
            })
            .optional(),
          osv: Toggle.optional(),
          gitleaks: Toggle.optional(),
          trivy: z
            .strictObject({
              enabled: z.boolean().default(true),
              /** Misconfigurations below this severity are not reported. */
              min_severity: LowerSeverity.default('MEDIUM'),
            })
            .optional(),
        })
        .optional(),
    })
    .optional(),
  knowledge_base: z
    .strictObject({
      /** Local knowledge base directory (default ~/.spinxsca/kb, or SPINXSCA_KB_DIR). */
      dir: z.string().optional(),
    })
    .optional(),
  ai: z
    .strictObject({
      level: z.enum(['off', 'explain', 'standard']).default('off'),
      provider: z.enum(['anthropic', 'openai-compatible', 'scripted']).default('anthropic'),
      model: z.string().min(1).optional(),
      /** openai-compatible: base URL of the self-hosted endpoint, e.g. http://llm.internal:8000/v1. */
      base_url: z.url().optional(),
      /** Environment variable holding the endpoint's API key (never the key itself). */
      api_key_env: z
        .string()
        .regex(/^[A-Z_][A-Z0-9_]*$/)
        .default('SPINXSCA_LLM_API_KEY'),
      /** What may reach a model (docs/architecture/06 section 3.2). */
      data_policy: z
        .strictObject({
          /** Files never sent: excluded from the roles' snapshot and withheld from evidence. */
          exclude_paths: z.array(z.string().min(1)).default([]),
          /** Only these providers may be configured (e.g. ["openai-compatible"] for on-prem only). */
          allowed_providers: z.array(z.enum(['anthropic', 'openai-compatible', 'scripted'])).optional(),
        })
        .optional(),
      effort: z.enum(['low', 'medium', 'high', 'xhigh', 'max']).default('high'),
      /** Server-side refusal fallback for the Claude API (ADR-020). */
      refusal_fallback: z.enum(['default', 'off']).default('default'),
      max_cost_usd_per_scan: z.number().positive().default(5),
      /** Upper bound of findings explained during one scan. */
      max_findings: z.number().int().positive().default(20),
      /** Redacted code excerpts are sent to the model only when this is true. */
      send_source_snippets: z.boolean().default(true),
    })
    .optional(),
  policy: z
    .strictObject({
      fail_on_severity: LowerSeverity.optional(),
      new_findings_only: z.boolean().default(true),
    })
    .optional(),
  /** Release Security Gate (docs/architecture/05 section 4; spinxsca gate). */
  gate: z
    .strictObject({
      /** The latest scan of the branch must be younger than this. */
      max_scan_age_hours: z.number().positive().default(72),
      /** Open findings at or above this severity block the release (all open findings, not only new). */
      fail_on_severity: LowerSeverity.default('HIGH'),
      /** Open dependency findings listed in CISA KEV block regardless of severity. */
      block_kev: z.boolean().default(true),
      /** Open dependency findings with an EPSS score at or above this block. */
      epss_threshold: z.number().min(0).max(1).optional(),
      require_complete_coverage: z.boolean().default(true),
      /** The knowledge base snapshot used by the scan must be younger than this. */
      max_kb_age_hours: z.number().positive().optional(),
    })
    .optional(),
  output: z
    .strictObject({
      formats: z.array(z.enum(['sarif', 'md', 'json'])).default(['sarif', 'md', 'json']),
    })
    .optional(),
});
export type SpinxscaConfig = z.infer<typeof SpinxscaConfig>;
export type SpinxscaConfigInput = z.input<typeof SpinxscaConfig>;
