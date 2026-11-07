import { z } from 'zod';
import type { Severity } from './common';
import { AUTO_ALLOWABLE_RISKS, AutonomyMode, ReviewerMode, RiskClass, TOOL_RISK } from './governance';

const LowerSeverity = z
  .enum(['critical', 'high', 'medium', 'low', 'info'])
  .transform((value) => value.toUpperCase() as Severity);

const Toggle = z.strictObject({ enabled: z.boolean().default(true) });

const ToolName = z.string().regex(/^[a-z][a-z0-9_]{0,63}$/, 'expected a tool name');

/** Governance of autonomous review (ADR-041). Operator configuration only; never read from the repository. */
const AutonomyConfig = z.strictObject({
  mode: AutonomyMode.default('supervised'),
  /** Reviewer model approving asks while a human is attended (autonomous mode only; never unattended). */
  reviewer: ReviewerMode.default('on'),
  reviewer_model: z.string().min(1).optional(),
  /**
   * Tools allowed without asking (L11). Repository writes, external actions, governance and egress
   * can never be auto-allowed.
   */
  auto_allow: z
    .array(ToolName)
    .default([])
    .superRefine((tools, ctx) => {
      for (const tool of tools) {
        const risk = TOOL_RISK[tool];
        if (!risk) ctx.addIssue({ code: 'custom', message: `unknown tool ${tool}` });
        else if (!AUTO_ALLOWABLE_RISKS.has(risk) || tool.startsWith('request_')) {
          ctx.addIssue({ code: 'custom', message: `${tool} (${risk}) cannot be auto-allowed` });
        }
      }
    }),
  /** Tools never offered to any persona. */
  deny_tools: z.array(ToolName).default([]),
  /** Extra protected path globs (CI, deployment, auth) flagged and never covered by standing rules. */
  extra_protected: z.array(z.string().min(1)).default([]),
  /** Raise the risk class of a tool; lowering is ignored by the policy engine. */
  risk_overrides: z.record(ToolName, RiskClass).default({}),
  budgets: z
    .strictObject({
      max_rounds: z.number().int().positive().default(6),
      max_cost_usd: z.number().positive().default(10),
      max_sandbox_runs: z.number().int().positive().default(60),
      max_sandbox_cpu_sec: z.number().int().positive().default(1800),
      max_wall_clock_min: z.number().int().positive().default(90),
      max_parallel_workers: z.number().int().min(1).max(6).default(3),
    })
    .optional(),
  /** Unattended runs refuse models without a known price unless this is true. */
  allow_unpriced: z.boolean().default(false),
  /**
   * Image of the agent's analysis shell, pinned by digest or local image id (pnpm toolbox:build).
   * Defaults to the pinned Node image (busybox tools only).
   */
  toolbox_image: z
    .string()
    .regex(/(^|@)sha256:[0-9a-f]{64}$/, 'pin the image: "<name>@sha256:<digest>" or "sha256:<image id>"')
    .optional(),
});

/** L3 controlled validation (ADR-045): PoC harnesses run in a network-less sandbox over a copy. */
const ValidationConfig = z.strictObject({
  /** When true, sandboxed PoC runs are allowed without asking (operator decision). */
  l3: z.boolean().default(false),
  max_runs_per_finding: z.number().int().min(1).max(10).default(3),
  timeout_sec: z.number().int().min(10).max(900).default(120),
  memory_mb: z.number().int().min(256).max(8192).default(1024),
});

/** Recon-first analysis for `--ai standard` and `--ai deep` (ADR-049). */
const ReconConfig = z.strictObject({
  enabled: z.boolean().default(true),
  /** Completeness re-passes per packet or logic item; 0 disables the critic. */
  critic_passes: z.number().int().min(0).max(2).default(1),
  /** Upper bound of LOGIC_AUDIT items seeded in a deep review case. */
  max_logic_items: z.number().int().min(1).max(16).default(8),
  /** Inject the deterministic resource/data-access census worksheet into prompts. */
  census: z.boolean().default(true),
  /** Blind second-opinion passes (hook only; values above 0 are not supported yet). */
  second_opinion: z.literal(0).default(0),
});

const Provenance = z.string().min(1).max(200);
/** Operator context pack (ADR-051): statements the source cannot establish, each with provenance. */
export const AiContextConfig = z.strictObject({
  /** Intended behaviours a naive reviewer would flag; become operator carve-outs. */
  accepted_risks: z.array(z.string().min(10).max(600)).max(30).default([]),
  roles: z
    .array(
      z.strictObject({ name: z.string().min(1).max(80), trust: z.string().min(1).max(400), provenance: Provenance }),
    )
    .max(20)
    .default([]),
  trust_claims: z
    .array(z.strictObject({ statement: z.string().min(1).max(400), provenance: Provenance }))
    .max(30)
    .default([]),
  business_invariants: z
    .array(z.strictObject({ statement: z.string().min(1).max(400), provenance: Provenance }))
    .max(30)
    .default([]),
});

const ModelAlias = z.string().regex(/^[a-z][a-z0-9_-]{0,31}$/, 'expected a model alias');
const RateLimitConfig = z.strictObject({
  rpm: z.number().int().positive().optional(),
  tpm: z.number().int().positive().optional(),
  concurrency: z.number().int().min(1).max(32).optional(),
});

/** One model endpoint the agent may use (ADR-053). Aliases are routed to roles through `ai.routing`. */
export const AiModelConfig = z.strictObject({
  provider: z.enum(['anthropic', 'openai-compatible', 'ollama', 'scripted']),
  model: z.string().min(1),
  /** openai-compatible: `http://host:8000/v1`; ollama: `http://host:11434`. */
  base_url: z.url().optional(),
  api_key_env: z
    .string()
    .regex(/^[A-Z_][A-Z0-9_]*$/)
    .optional(),
  /** Context window in tokens; detected from the endpoint or taken from the catalog when absent. */
  context_window: z.number().int().min(4096).max(2_000_000).optional(),
  max_output: z.number().int().min(256).max(128_000).optional(),
  /** `auto` follows the catalog; `prompted` renders tools into the prompt; `none` is single-shot JSON only. */
  tool_mode: z.enum(['auto', 'native', 'prompted', 'none']).default('auto'),
  temperature: z.number().min(0).max(2).optional(),
  /** Ollama only: context length the server loads the model with. */
  num_ctx: z.number().int().min(2048).optional(),
  stream: z.boolean().optional(),
  rate_limit: RateLimitConfig.optional(),
  tier: z.enum(['deep', 'fast', 'local']).optional(),
});
export type AiModelConfig = z.infer<typeof AiModelConfig>;

/** Which alias serves which role; unrouted roles fall back (judge/map/summarize -> fast -> deep). */
export const AiRoutingConfig = z.strictObject({
  deep: ModelAlias.optional(),
  fast: ModelAlias.optional(),
  judge: ModelAlias.optional(),
  map: ModelAlias.optional(),
  reduce: ModelAlias.optional(),
  summarize: ModelAlias.optional(),
});
export type AiRoutingConfig = z.infer<typeof AiRoutingConfig>;

/** Sharded map/reduce for large repositories (ADR-055). */
export const AiShardingConfig = z.strictObject({
  /** `auto` shards once the candidate set outgrows one investigation; small repositories keep the packet flow. */
  enabled: z.enum(['auto', 'on', 'off']).default('auto'),
  max_shards: z.number().int().min(1).max(512).default(64),
  max_files_per_shard: z.number().int().min(1).max(200).default(40),
  /** Share of the map model's effective window one shard may fill with source. */
  token_budget_ratio: z.number().min(0.1).max(0.6).default(0.35),
  /** Path segments that form a module (files of one module stay in one shard). */
  group_depth: z.number().int().min(1).max(6).default(3),
  /** Also investigate files without any selector, index, census or scanner signal. */
  include_zero_signal: z.boolean().default(false),
});
export type AiShardingConfig = z.infer<typeof AiShardingConfig>;

export const AiParallelConfig = z.strictObject({
  /** Concurrent shard investigations; bounded by the provider's concurrency limit. */
  map_workers: z.number().int().min(1).max(16).optional(),
  /** Concurrent explore sub-agents per role. */
  explore: z.number().int().min(1).max(8).default(3),
});
export type AiParallelConfig = z.infer<typeof AiParallelConfig>;
export type AiContextConfig = z.infer<typeof AiContextConfig>;

const RemediationConfig = z.strictObject({
  enabled: z.boolean().default(false),
  max_iterations: z.number().int().min(1).max(5).default(3),
  min_severity: LowerSeverity.default('HIGH'),
});

/** USD per million tokens for models missing from the built-in price table (self-hosted, new models). */
const PricingConfig = z.record(
  z.string().min(1),
  z.strictObject({
    input: z.number().nonnegative(),
    output: z.number().nonnegative(),
    cache_read: z.number().nonnegative().default(0),
  }),
);

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
      level: z.enum(['off', 'explain', 'standard', 'deep']).default('off'),
      provider: z.enum(['anthropic', 'openai-compatible', 'ollama', 'scripted']).default('anthropic'),
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
          allowed_providers: z.array(z.enum(['anthropic', 'openai-compatible', 'ollama', 'scripted'])).optional(),
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
      /** Recon-first logic analysis (ADR-049): ground truth before hunting, critic re-passes, census. */
      recon: ReconConfig.optional(),
      /** Operator-provided business context with provenance (ADR-051); claims are rechecked, never proof. */
      context: AiContextConfig.optional(),
      autonomy: AutonomyConfig.optional(),
      validation: ValidationConfig.optional(),
      remediation: RemediationConfig.optional(),
      pricing: PricingConfig.optional(),
      /** Named model endpoints (ADR-053); absent means one model from provider/model/base_url for every role. */
      models: z.record(ModelAlias, AiModelConfig).optional(),
      routing: AiRoutingConfig.optional(),
      sharding: AiShardingConfig.optional(),
      parallel: AiParallelConfig.optional(),
    })
    .superRefine((ai, ctx) => {
      for (const [role, alias] of Object.entries(ai.routing ?? {})) {
        if (alias && !ai.models?.[alias])
          ctx.addIssue({
            code: 'custom',
            path: ['routing', role],
            message: `ai.routing.${role} names unknown alias "${alias}"`,
          });
      }
      for (const [alias, m] of Object.entries(ai.models ?? {})) {
        if (m.provider !== 'anthropic' && m.provider !== 'scripted' && !m.base_url)
          ctx.addIssue({
            code: 'custom',
            path: ['models', alias, 'base_url'],
            message: `ai.models.${alias} (${m.provider}) needs base_url`,
          });
      }
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
      /**
       * AI severity downgrades and UNLIKELY classifications are not trusted by the CI policy and the
       * release gate unless this is true: the gate uses max(scanner severity, AI severity) and a human
       * disposition is needed to clear a finding (ADR-041).
       */
      trust_ai_downgrades: z.boolean().default(false),
      /**
       * Findings first reported by an AI role (not by a scanner) block the gate only when their
       * classification is at least this (ADR-050). CONFIRMED keeps the Phase 5 posture of not
       * trusting a model's word alone; POTENTIAL lets validated-but-uncertain logic findings block.
       */
      ai_discovered_min_classification: z.enum(['CONFIRMED', 'POTENTIAL']).default('CONFIRMED'),
    })
    .optional(),
  output: z
    .strictObject({
      formats: z.array(z.enum(['sarif', 'md', 'json'])).default(['sarif', 'md', 'json']),
      /** Include AI-discovered findings that are still POTENTIAL/BLOCKED in SARIF (they always appear in md/json). */
      sarif_include_unverified_ai: z.boolean().default(false),
    })
    .optional(),
});
export type SpinxscaConfig = z.infer<typeof SpinxscaConfig>;
export type SpinxscaConfigInput = z.input<typeof SpinxscaConfig>;
