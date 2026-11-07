import {
  AgentAssistant,
  AgentExplainer,
  AgentInvestigator,
  AgentMapReduceInvestigator,
  AgentRemediator,
  type DetectedProfile,
  type Effort,
  type LlmProvider,
  loadPromptBundle,
  type ReconOptions,
  scriptedExplainProvider,
  scriptedLogicProvider,
  scriptedMapProvider,
  scriptedRemediationProvider,
  weakModelProvider,
  withDataPolicy,
  withPromptedTools,
} from '@spinxsca/agent';
import type {
  FindingExplainer,
  Investigator,
  MapReduceInvestigator,
  ProjectAssistant,
  Remediator,
} from '@spinxsca/core';
import type {
  AiContextConfig,
  AiModelConfig,
  AiParallelConfig,
  AiRoutingConfig,
  AiShardingConfig,
} from '@spinxsca/schemas';
import { registryFor } from './models';
import { resolvePromptsDir } from './rules';

export type AiProviderKind = 'anthropic' | 'openai-compatible' | 'ollama' | 'scripted';

export interface AiExplainOptions {
  provider: AiProviderKind;
  model?: string;
  /** openai-compatible endpoint and the environment variable holding its key. */
  baseUrl?: string;
  apiKeyEnv?: string;
  /** Paths never sent to a model. */
  excludePaths?: readonly string[];
  effort: Effort;
  refusalFallback: 'default' | 'off';
  maxCostUsdPerFinding: number;
  /** Recon-first investigation settings (`ai.recon`, ADR-049). */
  recon?: ReconOptions;
  /** Operator context pack (`ai.context` or `--context-pack`, ADR-051). */
  context?: AiContextConfig;
  /** Named model endpoints and role routing (`ai.models`, `ai.routing`, ADR-053). */
  models?: Record<string, AiModelConfig>;
  routing?: AiRoutingConfig;
  /** `--ai-provider`/`--model` flags were given: ignore the alias table and use one model. */
  forceSingleModel?: boolean;
  /** Endpoint probes keyed by alias (filled by `withDetectedProfiles`). */
  detected?: Record<string, DetectedProfile>;
  sharding?: AiShardingConfig;
  parallel?: AiParallelConfig;
  /** Scripted doubles behind a weak prompted-tool model (`--ai-provider scripted-weak`). */
  weak?: boolean;
}

/** Builds the AI roles for a provider. Credentials are resolved by the SDK (env or `ant auth login`). */
export interface AiRoles {
  explainer: FindingExplainer;
  assistant: ProjectAssistant;
  investigator: Investigator;
  remediator: Remediator;
  /** Sharded investigation for large repositories (ADR-055); absent for the scripted provider. */
  mapReduce?: MapReduceInvestigator;
}

/** Tests can register a scripted remediation (replacement text) through this hook. */
export const scriptedRemediation: { replacement?: string; lines?: number } = {};

export function createAi(options: AiExplainOptions): AiRoles {
  const prompts = loadPromptBundle(resolvePromptsDir());
  let provider: () => LlmProvider;
  let investigationProvider: () => LlmProvider;
  let remediationProvider: () => LlmProvider;
  let mapReduce: MapReduceInvestigator | undefined;
  let summarizeFor: (() => LlmProvider) | undefined;
  if (options.provider === 'scripted') {
    // A weak double wraps every scripted role: prompted tools parsed from text, small window (ADR-054).
    const weaken = (factory: () => LlmProvider): (() => LlmProvider) =>
      options.weak ? () => withPromptedTools(weakModelProvider(factory())) : factory;
    provider = weaken(scriptedExplainProvider);
    investigationProvider = weaken(scriptedLogicProvider);
    remediationProvider = () =>
      scriptedRemediationProvider({
        replacement: scriptedRemediation.replacement ?? '',
        ...(scriptedRemediation.lines ? { lines: scriptedRemediation.lines } : {}),
      });
    mapReduce = new AgentMapReduceInvestigator({
      providers: { deep: weaken(scriptedMapProvider) },
      prompts,
      effort: options.effort,
      ...(options.recon ? { recon: options.recon } : {}),
      ...(options.context ? { context: options.context } : {}),
      ...(options.parallel?.map_workers ? { mapWorkers: options.parallel.map_workers } : {}),
      excludePaths: options.excludePaths ?? [],
    });
  } else {
    // Roles are routed through the registry (ADR-053): explanation and chat take the fast model when
    // one is routed, investigation and remediation the deep one; every alias shares one endpoint limiter.
    const registry = registryFor(options);
    const deep = registry.for('deep');
    provider = registry.routed('fast') ? registry.for('fast') : deep;
    investigationProvider = deep;
    remediationProvider = deep;
    const summarizeProvider =
      registry.routed('summarize') || registry.routed('fast') ? registry.for('summarize') : undefined;
    summarizeFor = summarizeProvider;
    mapReduce = new AgentMapReduceInvestigator({
      ...(summarizeProvider ? { summarizeProvider } : {}),
      providers: {
        deep,
        ...(registry.routed('map') || registry.routed('fast') ? { map: registry.for('map') } : {}),
        ...(registry.routed('reduce') ? { reduce: registry.for('reduce') } : {}),
      },
      prompts,
      effort: options.effort,
      ...(options.recon ? { recon: options.recon } : {}),
      ...(options.context ? { context: options.context } : {}),
      ...(options.parallel?.map_workers ? { mapWorkers: options.parallel.map_workers } : {}),
      excludePaths: options.excludePaths ?? [],
    });
  }
  const policy = { excludePaths: options.excludePaths ?? [] };
  return {
    explainer: withDataPolicy(
      new AgentExplainer({
        provider,
        prompts,
        effort: options.effort,
        maxCostUsdPerFinding: options.maxCostUsdPerFinding,
      }),
      policy,
    ),
    assistant: withDataPolicy(
      new AgentAssistant({
        provider,
        prompts,
        effort: options.effort,
        maxCostUsd: options.maxCostUsdPerFinding,
      }),
      policy,
    ),
    investigator: withDataPolicy(
      new AgentInvestigator({
        provider: investigationProvider,
        ...(summarizeFor ? { summarizeProvider: summarizeFor } : {}),
        prompts,
        effort: options.effort,
        ...(options.recon ? { recon: options.recon } : {}),
        ...(options.context ? { context: options.context } : {}),
      }),
      policy,
    ),
    remediator: withDataPolicy(
      new AgentRemediator({
        provider: remediationProvider,
        prompts,
        effort: options.effort,
        maxCostUsd: options.maxCostUsdPerFinding,
      }),
      policy,
    ),
    ...(mapReduce ? { mapReduce } : {}),
  };
}
