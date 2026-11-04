import { join } from 'node:path';
import {
  AgentAutonomousReviewer,
  AnthropicProvider,
  type AutonomyConfig,
  type CaseEvent,
  compileDataPolicy,
  DEFAULT_ANTHROPIC_MODEL,
  type HumanApprover,
  type LlmProvider,
  OpenAICompatibleProvider,
  scriptedReviewProvider,
} from '@spinxsca/agent';
import { dependencyUsage } from '@spinxsca/code-intel';
import type { DependencyInfo, ReviewPortContext, ReviewPorts } from '@spinxsca/core';
import {
  DEFAULT_TOOLBOX_IMAGE,
  localValidationPort,
  materializeRedactedCopy,
  NODE_IMAGE,
  PYTHON_IMAGE,
  runAnalysisShell,
} from '@spinxsca/sandbox';
import { createProbePort, gitHistorySecrets, imageRef, PINNED_IMAGES, parseLockfiles } from '@spinxsca/scanners';
import type { SpinxscaConfig } from '@spinxsca/schemas';
import type { AiExplainOptions } from './ai';
import type { LoadedConfig } from './config';
import type { Engine } from './engine';
import { resolvePromptsDir } from './rules';
import { resolvePlaybooksDir } from './rules-playbooks';
import { CliError } from './ui';

export interface ReviewFlags {
  mode?: string;
  reviewer?: string;
  goal?: string;
  objectives?: string[];
  budgetUsd?: string;
  maxRounds?: string;
  l3?: boolean;
  fix?: boolean;
  unattended?: boolean;
}

export const DEFAULT_GOAL =
  'Review this codebase for real, exploitable security risks: confirm or refute every scanner finding with evidence, decide whether vulnerable dependencies are reachable, look for authorization and logic flaws the scanners miss, and report what could not be covered.';

/** Autonomy settings: operator configuration overridden by command flags (never by the repository). */
export function autonomyConfig(loaded: LoadedConfig, flags: ReviewFlags, maxCostUsd: number): AutonomyConfig {
  const config: SpinxscaConfig = loaded.config;
  const a = config.ai?.autonomy;
  const v = config.ai?.validation;
  const mode = (flags.mode ?? a?.mode ?? 'supervised') as AutonomyConfig['mode'];
  if (!['observe', 'supervised', 'autonomous'].includes(mode)) {
    throw new CliError(`unknown --mode "${flags.mode}" (expected observe, supervised or autonomous)`);
  }
  const reviewer = (flags.reviewer ?? a?.reviewer ?? 'on') as AutonomyConfig['reviewer'];
  if (!['off', 'shadow', 'on'].includes(reviewer)) throw new CliError(`unknown --reviewer "${flags.reviewer}"`);
  const number = (value: string | undefined, fallback: number, name: string) => {
    if (value === undefined) return fallback;
    const n = Number(value);
    if (!Number.isFinite(n) || n <= 0) throw new CliError(`${name} must be a positive number`);
    return n;
  };
  const budgets = a?.budgets;
  return {
    mode,
    reviewer,
    attended: !flags.unattended && Boolean(process.stdin.isTTY),
    autoAllow: a?.auto_allow ?? [],
    denyTools: a?.deny_tools ?? [],
    extraProtected: a?.extra_protected ?? [],
    riskOverrides: a?.risk_overrides ?? {},
    maxRounds: number(flags.maxRounds, budgets?.max_rounds ?? 6, '--max-rounds'),
    maxCostUsd: number(flags.budgetUsd, Math.min(budgets?.max_cost_usd ?? 10, maxCostUsd), '--budget-usd'),
    maxSandboxRuns: budgets?.max_sandbox_runs ?? 60,
    maxSandboxCpuSec: budgets?.max_sandbox_cpu_sec ?? 1800,
    maxWallClockMin: budgets?.max_wall_clock_min ?? 90,
    maxParallel: budgets?.max_parallel_workers ?? 3,
    allowUnpriced: a?.allow_unpriced ?? false,
    // L3 auto-runs only when the operator configuration enables it; --l3 merely asks for PoCs.
    l3: flags.l3 === false ? false : (v?.l3 ?? false) || flags.l3 === true,
    maxRunsPerFinding: v?.max_runs_per_finding ?? 3,
    remediation: flags.fix ?? config.ai?.remediation?.enabled ?? false,
    dataPolicyExclude: config.ai?.data_policy?.exclude_paths ?? [],
    ...(config.ai?.data_policy?.allowed_providers ? { allowedProviders: config.ai.data_policy.allowed_providers } : {}),
    ...(config.ai?.pricing ? { pricing: config.ai.pricing } : {}),
    protectedRoots: [loaded.path, config.knowledge_base?.dir].filter((p): p is string => Boolean(p)),
  };
}

export function providerFor(ai: AiExplainOptions, model?: string): () => LlmProvider {
  if (ai.provider === 'scripted') return scriptedReviewProvider;
  if (ai.provider === 'openai-compatible') {
    if (!ai.baseUrl || !ai.model) throw new CliError('ai.provider openai-compatible needs ai.base_url and ai.model');
    const apiKey = process.env[ai.apiKeyEnv ?? 'SPINXSCA_LLM_API_KEY'];
    const p = new OpenAICompatibleProvider({
      baseUrl: ai.baseUrl,
      model: model ?? ai.model,
      ...(apiKey ? { apiKey } : {}),
    });
    return () => p;
  }
  let p: AnthropicProvider;
  try {
    p = new AnthropicProvider({
      model: model ?? ai.model ?? DEFAULT_ANTHROPIC_MODEL,
      effort: ai.effort,
      fallbacks: ai.refusalFallback,
    });
  } catch (err) {
    throw new CliError(
      `Claude API client could not be created (${(err as Error).message}). Set ANTHROPIC_API_KEY or run \`ant auth login\`.`,
    );
  }
  return () => p;
}

export function createReviewer(o: {
  ai: AiExplainOptions;
  loaded: LoadedConfig;
  config: AutonomyConfig;
  goal?: string;
  objectives?: readonly string[];
  human?: HumanApprover;
  onEvent?: (event: CaseEvent) => void;
  /** Wraps the model provider (evaluation records every request). */
  wrapProvider?: (p: () => LlmProvider) => () => LlmProvider;
}): AgentAutonomousReviewer {
  const provider = o.wrapProvider ? o.wrapProvider(providerFor(o.ai)) : providerFor(o.ai);
  const reviewerModel = o.loaded.config.ai?.autonomy?.reviewer_model;
  return new AgentAutonomousReviewer({
    provider,
    judgeProvider: reviewerModel ? providerFor(o.ai, reviewerModel) : provider,
    promptsDir: resolvePromptsDir(),
    playbooksDir: resolvePlaybooksDir(),
    config: o.config,
    goal: o.goal ?? DEFAULT_GOAL,
    ...(o.objectives?.length ? { objectives: o.objectives } : {}),
    ...(o.human ? { human: o.human } : {}),
    effort: o.ai.effort,
    ...(o.onEvent ? { onEvent: o.onEvent } : {}),
  });
}

/**
 * Ports of a review case over the local runtime (ADR-043): probes through the configured scanners,
 * lockfile inventory and index reachability, knowledge base lookups as of the scan's snapshot, the
 * analysis shell over a redacted copy, and the git history secrets scan.
 */
export function reviewPorts(engine: Engine, loaded: LoadedConfig): (ctx: ReviewPortContext) => Promise<ReviewPorts> {
  return async (ctx) => {
    if (!engine.cases) throw new CliError('this runtime has no case store');
    const workDir = join(engine.stateDir, 'tmp', ctx.scan.scanId, 'case');
    const paths = ctx.files.map((f) => f.path);
    const kbRef = ctx.scan.manifest.knowledgeBase ?? undefined;
    let inventory: Promise<DependencyInfo[]> | undefined;
    const inventoryOnce = () => {
      inventory ??= parseLockfiles(engine.source, paths);
      return inventory;
    };
    const allows = compileDataPolicy({ excludePaths: loaded.config.ai?.data_policy?.exclude_paths ?? [] });
    let copy: Promise<string> | undefined;
    const toolbox = loaded.config.ai?.autonomy?.toolbox_image ?? DEFAULT_TOOLBOX_IMAGE;
    const scannerImages: Record<string, string> = Object.fromEntries(
      engine.scanners.map((a) => [a.describe().id, a.describe().image]),
    );
    scannerImages.semgrep ??= imageRef(PINNED_IMAGES.semgrep);
    return {
      cases: engine.cases,
      probe: createProbePort({
        runner: ctx.runner,
        scanId: ctx.scan.scanId,
        snapshot: ctx.snapshot,
        source: engine.source,
        sandbox: engine.sandbox,
        artifacts: engine.artifacts,
        logger: engine.logger,
        exclude: ctx.scan.manifest.scope.exclude,
        adapters: new Map(engine.scanners.map((a) => [a.describe().id, a])),
        ...(kbRef ? { knowledgeBase: kbRef } : {}),
        workRoot: join(workDir, 'probes'),
      }),
      dependencies: {
        inventory: inventoryOnce,
        reachability: async (input) => {
          const direct = (await inventoryOnce()).find((r) => r.name === input.name)?.direct;
          if (!ctx.graph) {
            return {
              level: 'UNKNOWN_TRANSITIVE',
              confidence: 'LOW',
              symbolSource: 'none',
              importSites: [],
              callSites: [],
              entrypoints: [],
              detail: 'no code index for this scan',
            };
          }
          return dependencyUsage(ctx.graph, { ...input, ...(direct !== undefined ? { direct } : {}) });
        },
      },
      ...(engine.kb
        ? { kb: { advisories: (ids) => (engine.kb as NonNullable<Engine['kb']>).advisories(kbRef?.snapshotId, ids) } }
        : {}),
      shell: {
        exec: async (command, options) => {
          copy ??= materializeRedactedCopy({
            source: engine.source,
            paths,
            dest: join(workDir, 'analysis', 'src'),
            allows,
            redactions: ctx.redactions,
            scrubber: ctx.scrubber,
          }).then((c) => c.root);
          return runAnalysisShell({
            sandbox: engine.sandbox,
            root: await copy,
            command,
            image: toolbox,
            ...(options?.timeoutSec ? { timeoutSec: options.timeoutSec } : {}),
            ...(options?.signal ? { signal: options.signal } : {}),
          });
        },
      },
      history: gitHistorySecrets({
        sandbox: engine.sandbox,
        repoRoot: engine.scanRoot,
        workDir: join(workDir, 'history'),
      }),
      validation: localValidationPort({
        sandbox: engine.sandbox,
        source: engine.source,
        paths,
        root: join(workDir, 'validation'),
        allows,
        redactions: ctx.redactions,
        scrubber: ctx.scrubber,
        timeoutSec: loaded.config.ai?.validation?.timeout_sec ?? 120,
        memoryMb: loaded.config.ai?.validation?.memory_mb ?? 1024,
      }),
      images: {
        toolbox,
        scanners: scannerImages,
        interpreters: { node: NODE_IMAGE, python3: PYTHON_IMAGE, python: PYTHON_IMAGE },
      },
      workDir,
    };
  };
}
