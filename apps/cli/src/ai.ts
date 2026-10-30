import {
  AgentAssistant,
  AgentExplainer,
  AgentInvestigator,
  AgentRemediator,
  AnthropicProvider,
  DEFAULT_ANTHROPIC_MODEL,
  type Effort,
  type LlmProvider,
  loadPromptBundle,
  OpenAICompatibleProvider,
  scriptedExplainProvider,
  scriptedInvestigationProvider,
  scriptedRemediationProvider,
  withDataPolicy,
} from '@spinxsca/agent';
import type { FindingExplainer, Investigator, ProjectAssistant, Remediator } from '@spinxsca/core';
import { resolvePromptsDir } from './rules';
import { CliError } from './ui';

export interface AiExplainOptions {
  provider: 'anthropic' | 'openai-compatible' | 'scripted';
  model?: string;
  /** openai-compatible endpoint and the environment variable holding its key. */
  baseUrl?: string;
  apiKeyEnv?: string;
  /** Paths never sent to a model. */
  excludePaths?: readonly string[];
  effort: Effort;
  refusalFallback: 'default' | 'off';
  maxCostUsdPerFinding: number;
}

/** Builds the AI roles for a provider. Credentials are resolved by the SDK (env or `ant auth login`). */
export interface AiRoles {
  explainer: FindingExplainer;
  assistant: ProjectAssistant;
  investigator: Investigator;
  remediator: Remediator;
}

/** Tests can register a scripted remediation (replacement text) through this hook. */
export const scriptedRemediation: { replacement?: string; lines?: number } = {};

export function createAi(options: AiExplainOptions): AiRoles {
  const prompts = loadPromptBundle(resolvePromptsDir());
  let provider: () => LlmProvider;
  let investigationProvider: () => LlmProvider;
  let remediationProvider: () => LlmProvider;
  if (options.provider === 'scripted') {
    provider = scriptedExplainProvider;
    investigationProvider = scriptedInvestigationProvider;
    remediationProvider = () =>
      scriptedRemediationProvider({
        replacement: scriptedRemediation.replacement ?? '',
        ...(scriptedRemediation.lines ? { lines: scriptedRemediation.lines } : {}),
      });
  } else if (options.provider === 'openai-compatible') {
    if (!options.baseUrl || !options.model)
      throw new CliError('ai.provider openai-compatible needs ai.base_url and ai.model');
    const apiKey = process.env[options.apiKeyEnv ?? 'SPINXSCA_LLM_API_KEY'];
    const shared = new OpenAICompatibleProvider({
      baseUrl: options.baseUrl,
      model: options.model,
      ...(apiKey ? { apiKey } : {}),
    });
    provider = () => shared;
    investigationProvider = provider;
    remediationProvider = provider;
  } else {
    let shared: AnthropicProvider;
    try {
      shared = new AnthropicProvider({
        model: options.model ?? DEFAULT_ANTHROPIC_MODEL,
        effort: options.effort,
        fallbacks: options.refusalFallback,
      });
    } catch (err) {
      throw new CliError(
        `Claude API client could not be created (${(err as Error).message}). Set ANTHROPIC_API_KEY or run \`ant auth login\`.`,
      );
    }
    provider = () => shared;
    investigationProvider = provider;
    remediationProvider = provider;
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
      new AgentInvestigator({ provider: investigationProvider, prompts, effort: options.effort }),
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
  };
}
