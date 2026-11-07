import type { AiModelConfig, AiRoutingConfig } from '@spinxsca/schemas';
import { AnthropicProvider } from './anthropic';
import { type ModelProfile, type ProfileOverrides, resolveProfile, type ToolMode } from './catalog';
import { type DetectedProfile, detectModelProfile } from './detect';
import { OllamaProvider } from './ollama';
import { OpenAICompatibleProvider } from './openai-compatible';
import { withPromptedTools } from './prompted-tools';
import { defaultRateLimit, RateLimiter, withRateLimit } from './rate-limit';
import type { Effort, LlmProvider } from './types';

/** Roles a model can be routed to (ADR-053). */
export type RoleKey = 'deep' | 'fast' | 'judge' | 'map' | 'reduce' | 'summarize';

const FALLBACK: Record<RoleKey, RoleKey[]> = {
  deep: [],
  fast: ['deep'],
  judge: ['fast', 'deep'],
  map: ['fast', 'deep'],
  reduce: ['deep'],
  summarize: ['fast', 'deep'],
};

export interface ResolvedModel {
  alias: string;
  config: AiModelConfig;
  profile: ModelProfile;
  /** Tool mode after `auto` is resolved against the profile. */
  toolMode: ToolMode;
  limiter: RateLimiter;
}

export interface ProviderRegistry {
  /** Provider factory for a role (one shared instance per alias). */
  for(role: RoleKey): () => LlmProvider;
  aliasOf(role: RoleKey): string;
  resolved(alias: string): ResolvedModel | undefined;
  aliases(): string[];
  /** True when the role is routed explicitly (not through a fallback). */
  routed(role: RoleKey): boolean;
}

export interface RegistryInput {
  models: Record<string, AiModelConfig>;
  routing?: AiRoutingConfig;
  env?: NodeJS.ProcessEnv;
  /** Endpoint probes keyed by alias (`detectRegistryProfiles`). */
  detected?: Record<string, DetectedProfile>;
  effort?: Effort;
  refusalFallback?: 'default' | 'off';
  fetch?: typeof fetch;
  /** Builds the provider of a `scripted` alias (tests and CI evals choose the double per role). */
  scripted?: (alias: string, config: AiModelConfig, role: RoleKey) => LlmProvider;
  /** Wraps every built provider (evaluation recording). */
  wrap?: (provider: LlmProvider, alias: string) => LlmProvider;
}

/** Profile overrides an operator can express in `ai.models.<alias>`, merged with detection results. */
export function overridesFor(config: AiModelConfig, detected?: DetectedProfile): ProfileOverrides {
  const contextWindow = config.context_window ?? config.num_ctx ?? detected?.numCtx ?? detected?.contextWindow;
  return {
    ...(contextWindow !== undefined ? { contextWindow } : {}),
    ...(config.max_output !== undefined ? { maxOutput: config.max_output } : {}),
    ...(config.tool_mode !== 'auto' ? { toolMode: config.tool_mode } : {}),
    ...(config.tier ? { tier: config.tier } : {}),
  };
}

/** Probes every non-Anthropic, non-scripted alias; failures leave the alias undetected. */
export async function detectRegistryProfiles(
  models: Record<string, AiModelConfig>,
  env: NodeJS.ProcessEnv = process.env,
  fetchImpl?: typeof fetch,
): Promise<Record<string, DetectedProfile>> {
  const out: Record<string, DetectedProfile> = {};
  await Promise.all(
    Object.entries(models).map(async ([alias, m]) => {
      if (m.provider === 'anthropic' || m.provider === 'scripted' || !m.base_url) return;
      const apiKey = m.api_key_env ? env[m.api_key_env] : undefined;
      out[alias] = await detectModelProfile({
        baseUrl: m.base_url,
        model: m.model,
        ...(apiKey ? { apiKey } : {}),
        ...(fetchImpl ? { fetch: fetchImpl } : {}),
      });
    }),
  );
  return out;
}

/**
 * Builds providers for every alias and routes roles to them. Providers are created lazily (an
 * Anthropic client needs credentials) and shared per alias, so one rate limiter governs all roles
 * that use the same endpoint.
 */
export function buildRegistry(input: RegistryInput): ProviderRegistry {
  const env = input.env ?? process.env;
  const routing = input.routing ?? {};
  const aliases = Object.keys(input.models);
  if (aliases.length === 0) throw new Error('ai.models is empty');
  const resolved = new Map<string, ResolvedModel>();
  for (const [alias, config] of Object.entries(input.models)) {
    const profile = resolveProfile(config.model, overridesFor(config, input.detected?.[alias]));
    const toolMode: ToolMode = config.tool_mode === 'auto' ? profile.toolMode : config.tool_mode;
    const limit = config.rate_limit ?? defaultRateLimit(config.provider);
    resolved.set(alias, {
      alias,
      config,
      profile: { ...profile, toolMode },
      toolMode,
      limiter: new RateLimiter(limit),
    });
  }
  const instances = new Map<string, LlmProvider>();
  const build = (alias: string, role: RoleKey): LlmProvider => {
    // Scripted doubles keep per-run state and are rebuilt per call; real providers are shared.
    const cached = instances.get(alias);
    if (cached) return cached;
    const r = resolved.get(alias) as ResolvedModel;
    const { config, profile } = r;
    const apiKey = config.api_key_env ? env[config.api_key_env] : env.SPINXSCA_LLM_API_KEY;
    let provider: LlmProvider;
    switch (config.provider) {
      case 'scripted':
        provider =
          input.scripted?.(alias, config, role) ??
          (() => {
            throw new Error(`alias ${alias}: no scripted provider factory registered`);
          })();
        break;
      case 'anthropic':
        provider = new AnthropicProvider({
          model: config.model,
          ...(input.effort ? { effort: input.effort } : {}),
          ...(input.refusalFallback ? { fallbacks: input.refusalFallback } : {}),
        });
        break;
      case 'ollama':
        provider = new OllamaProvider({
          baseUrl: config.base_url as string,
          model: config.model,
          numCtx: config.num_ctx ?? profile.contextWindow,
          profile: { ...overridesFor(config, input.detected?.[alias]), toolMode: r.toolMode },
          ...(config.temperature !== undefined ? { temperature: config.temperature } : {}),
          ...(input.fetch ? { fetch: input.fetch } : {}),
        });
        break;
      default:
        provider = new OpenAICompatibleProvider({
          baseUrl: config.base_url as string,
          model: config.model,
          ...(apiKey ? { apiKey } : {}),
          profile: { ...overridesFor(config, input.detected?.[alias]), toolMode: r.toolMode },
          ...(config.stream !== undefined ? { stream: config.stream } : {}),
          ...(config.temperature !== undefined ? { temperature: config.temperature } : {}),
          ...(input.fetch ? { fetch: input.fetch } : {}),
        });
    }
    if (r.toolMode === 'prompted' && config.provider !== 'anthropic' && config.provider !== 'scripted')
      provider = withPromptedTools(provider);
    provider = withRateLimit(provider, r.limiter);
    if (input.wrap) provider = input.wrap(provider, alias);
    if (config.provider !== 'scripted') instances.set(alias, provider);
    return provider;
  };
  const aliasOf = (role: RoleKey): string => {
    const direct = routing[role];
    if (direct) return direct;
    for (const fallback of FALLBACK[role]) {
      const alias = routing[fallback];
      if (alias) return alias;
    }
    return routing.deep ?? (aliases.includes('default') ? 'default' : (aliases[0] as string));
  };
  return {
    for: (role) => {
      const alias = aliasOf(role);
      return () => build(alias, role);
    },
    aliasOf,
    resolved: (alias) => resolved.get(alias),
    aliases: () => [...aliases],
    routed: (role) => Boolean(routing[role]),
  };
}
