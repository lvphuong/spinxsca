import {
  buildRegistry,
  DEFAULT_ANTHROPIC_MODEL,
  type DetectedProfile,
  detectRegistryProfiles,
  type LlmProvider,
  type ProviderRegistry,
  type RoleKey,
  scriptedLogicProvider,
} from '@spinxsca/agent';
import type { AiModelConfig, AiRoutingConfig } from '@spinxsca/schemas';
import type { AiExplainOptions } from './ai';
import { CliError } from './ui';

/**
 * Model routing for the CLI (ADR-053). Operators either describe several endpoints in `ai.models`
 * and route roles through `ai.routing`, or keep the single `ai.provider/model/base_url` which
 * becomes the alias `default` serving every role. One registry (and so one rate limiter per
 * endpoint) is shared by every role created from the same options object.
 */
const registries = new WeakMap<AiExplainOptions, ProviderRegistry>();
const detections = new Map<string, Promise<DetectedProfile>>();

/** Alias table implied by the options: the configured table, or one `default` alias from the legacy fields. */
export function modelsFor(options: AiExplainOptions): {
  models: Record<string, AiModelConfig>;
  routing: AiRoutingConfig;
} {
  if (options.models && Object.keys(options.models).length && !options.forceSingleModel) {
    const models = { ...options.models };
    const routing = { ...(options.routing ?? {}) };
    // `--model` keeps overriding the model answering the deep role.
    if (options.model) {
      const alias = routing.deep ?? Object.keys(models)[0];
      if (alias && models[alias]) models[alias] = { ...(models[alias] as AiModelConfig), model: options.model };
    }
    return { models, routing };
  }
  if (options.provider !== 'anthropic' && options.provider !== 'scripted' && (!options.baseUrl || !options.model))
    throw new CliError(`ai.provider ${options.provider} needs ai.base_url and ai.model (or an ai.models table)`);
  return {
    models: {
      default: {
        provider: options.provider,
        model: options.model ?? (options.provider === 'anthropic' ? DEFAULT_ANTHROPIC_MODEL : 'scripted'),
        ...(options.baseUrl ? { base_url: options.baseUrl } : {}),
        api_key_env: options.apiKeyEnv ?? 'SPINXSCA_LLM_API_KEY',
        tool_mode: 'auto',
      },
    },
    routing: {},
  };
}

/** The registry for these options, built once. Anthropic clients are created lazily by the registry. */
export function registryFor(options: AiExplainOptions, scripted?: (role: RoleKey) => LlmProvider): ProviderRegistry {
  const cached = registries.get(options);
  if (cached) return cached;
  const { models, routing } = modelsFor(options);
  let registry: ProviderRegistry;
  try {
    registry = buildRegistry({
      models,
      routing,
      effort: options.effort,
      refusalFallback: options.refusalFallback,
      ...(options.detected ? { detected: options.detected } : {}),
      scripted: (_alias, _config, role) => (scripted ? scripted(role) : scriptedLogicProvider()),
    });
  } catch (err) {
    throw new CliError(`AI models could not be configured: ${(err as Error).message}`);
  }
  registries.set(options, registry);
  return registry;
}

/**
 * Probes self-hosted endpoints for their context length once per process (ADR-053) and returns the
 * options with `detected` filled, so profiles reflect the running server rather than a guess.
 * Aliases with an explicit `context_window` are not probed.
 */
export async function withDetectedProfiles(options: AiExplainOptions): Promise<AiExplainOptions> {
  if (options.provider === 'scripted' || options.detected) return options;
  const { models } = modelsFor(options);
  const pending = Object.fromEntries(
    Object.entries(models).filter(
      ([, m]) =>
        m.provider !== 'anthropic' && m.provider !== 'scripted' && m.base_url && !m.context_window && !m.num_ctx,
    ),
  );
  if (Object.keys(pending).length === 0) return options;
  const detected: Record<string, DetectedProfile> = {};
  await Promise.all(
    Object.entries(pending).map(async ([alias, m]) => {
      const key = `${m.base_url}|${m.model}`;
      let probe = detections.get(key);
      if (!probe) {
        probe = detectRegistryProfiles({ [alias]: m }).then((r) => r[alias] ?? { source: 'none' });
        detections.set(key, probe);
      }
      detected[alias] = await probe;
    }),
  );
  return { ...options, detected };
}
