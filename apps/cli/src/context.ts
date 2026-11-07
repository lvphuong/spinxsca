import { readFileSync } from 'node:fs';
import { userInfo } from 'node:os';
import { resolve } from 'node:path';
import { createSecretScrubber } from '@spinxsca/core';
import { AiContextConfig } from '@spinxsca/schemas';
import { parse as parseYaml } from 'yaml';
import type { AiExplainOptions } from './ai';
import { type LoadedConfig, loadConfig } from './config';
import { type Engine, openEngine } from './engine';
import { withDetectedProfiles } from './models';
import { CliError, createLogger } from './ui';

export interface CommonOptions {
  config?: string;
  stateDir?: string;
  kbDir?: string;
  verbose?: boolean;
  json?: boolean;
}

export interface AiFlags {
  ai?: string;
  aiProvider?: string;
  model?: string;
  maxCost?: string;
  /** Path of an operator context pack (ADR-051); overrides `ai.context` of the configuration. */
  contextPack?: string;
}

/**
 * Loads a context pack from a file chosen by the operator (never discovered in the scanned
 * repository). Claims must not carry secrets: the pack is rejected when the scrubber detects one.
 */
export function loadContextPack(path: string): AiContextConfig {
  let text: string;
  try {
    text = readFileSync(resolve(path), 'utf8');
  } catch (err) {
    throw new CliError(`cannot read context pack ${path}: ${(err as Error).message}`);
  }
  if (createSecretScrubber().detects(text))
    throw new CliError(
      `context pack ${path} looks like it contains a secret; describe the claim, do not paste credentials`,
    );
  const parsed = AiContextConfig.safeParse(parseYaml(text) ?? {});
  if (!parsed.success)
    throw new CliError(
      `invalid context pack ${path}:\n${parsed.error.issues.map((i) => `- ${i.path.join('.')}: ${i.message}`).join('\n')}`,
    );
  return parsed.data;
}

/** Opens the engine for a command and always closes it. */
export async function withEngine<T>(
  path: string | undefined,
  options: CommonOptions & { aiConfig?: AiExplainOptions },
  fn: (engine: Engine, loaded: LoadedConfig) => Promise<T>,
): Promise<T> {
  const loaded = loadConfig(options.config);
  // Self-hosted endpoints are asked for their context length once, before any role is built (ADR-053).
  const aiConfig = options.aiConfig ? await withDetectedProfiles(options.aiConfig) : undefined;
  if (aiConfig && options.aiConfig) Object.assign(options.aiConfig, aiConfig);
  const engine = openEngine({
    scanRoot: path ?? '.',
    config: loaded,
    logger: createLogger(Boolean(options.verbose)),
    ...(options.stateDir ? { stateDir: options.stateDir } : {}),
    ...(options.kbDir ? { kbDir: options.kbDir } : {}),
    ...(options.aiConfig ? { ai: options.aiConfig } : {}),
  });
  try {
    return await fn(engine, loaded);
  } finally {
    engine.close();
  }
}

/**
 * Fails early, before any AI call, when a finding id is unknown in this state directory. Finding
 * ids belong to the state directory of the scanned path, so the usual cause is a missing scan.
 */
export async function requireFinding(engine: Engine, findingId: string, path: string | undefined): Promise<void> {
  if (await engine.repo.getFinding(findingId)) return;
  const target = path ?? '.';
  const project = await engine.repo.getProject();
  const ids = project ? (await engine.repo.listFindings(project.project.projectId)).map((f) => f.findingId).sort() : [];
  if (ids.length === 0) {
    throw new CliError(
      `finding ${findingId} not found: no findings recorded in ${engine.stateDir}. Run \`spinxsca scan ${target}\` first (finding ids belong to the scanned path's state directory).`,
    );
  }
  const shown = ids.length > 10 ? `${ids.slice(0, 10).join(', ')}, … (${ids.length} total)` : ids.join(', ');
  throw new CliError(
    `finding ${findingId} not found in ${engine.stateDir}; known findings: ${shown}. See \`spinxsca findings list ${target}\`.`,
  );
}

/** AI settings from config overridden by flags; null when AI is not requested. */
export function aiOptions(
  loaded: LoadedConfig,
  flags: AiFlags,
  force = false,
): (AiExplainOptions & { level: 'explain' | 'standard' | 'deep'; maxCostUsd: number; maxFindings: number }) | null {
  const ai = loaded.config.ai;
  const level = flags.ai ?? ai?.level ?? 'off';
  if (!['off', 'explain', 'standard', 'deep'].includes(level)) {
    throw new CliError(`unknown --ai level "${level}" (expected off, explain, standard or deep)`);
  }
  if (level === 'off' && !force) return null;
  if (ai && ai.send_source_snippets === false) {
    throw new CliError('AI is disabled for this project: ai.send_source_snippets is false in the configuration');
  }
  // `scripted-weak` is a CLI-only alias: the scripted doubles behind a weak prompted-tool model (ADR-054).
  const weak = flags.aiProvider === 'scripted-weak';
  const provider = (
    weak ? 'scripted' : (flags.aiProvider ?? ai?.provider ?? 'anthropic')
  ) as AiExplainOptions['provider'];
  if (!['anthropic', 'openai-compatible', 'ollama', 'scripted'].includes(provider))
    throw new CliError(`unknown AI provider "${provider}"`);
  const allowed = ai?.data_policy?.allowed_providers;
  if (allowed && !allowed.includes(provider)) {
    throw new CliError(
      `AI provider "${provider}" is not allowed by ai.data_policy.allowed_providers (${allowed.join(', ')})`,
    );
  }
  for (const [alias, m] of Object.entries(ai?.models ?? {})) {
    if (allowed && !allowed.includes(m.provider))
      throw new CliError(
        `ai.models.${alias} uses provider "${m.provider}" not allowed by ai.data_policy.allowed_providers`,
      );
  }
  const maxCost = flags.maxCost !== undefined ? Number(flags.maxCost) : (ai?.max_cost_usd_per_scan ?? 5);
  if (!Number.isFinite(maxCost) || maxCost <= 0) throw new CliError('--max-cost must be a positive number of USD');
  return {
    level: level === 'standard' || level === 'deep' ? level : 'explain',
    provider,
    ...((flags.model ?? ai?.model) ? { model: (flags.model ?? ai?.model) as string } : {}),
    ...(ai?.base_url ? { baseUrl: ai.base_url } : {}),
    ...(ai?.api_key_env ? { apiKeyEnv: ai.api_key_env } : {}),
    ...(ai?.data_policy?.exclude_paths.length ? { excludePaths: ai.data_policy.exclude_paths } : {}),
    // `--ai-provider` names one model explicitly; the alias table then stays out of the way (ADR-053).
    ...(ai?.models && Object.keys(ai.models).length ? { models: ai.models } : {}),
    ...(ai?.routing ? { routing: ai.routing } : {}),
    ...(flags.aiProvider ? { forceSingleModel: true } : {}),
    ...(weak ? { weak: true } : {}),
    ...(ai?.sharding ? { sharding: ai.sharding } : {}),
    ...(ai?.parallel ? { parallel: ai.parallel } : {}),
    effort: ai?.effort ?? 'high',
    refusalFallback: ai?.refusal_fallback ?? 'default',
    maxCostUsdPerFinding: maxCost,
    maxCostUsd: maxCost,
    maxFindings: ai?.max_findings ?? 20,
    ...(ai?.recon
      ? {
          recon: {
            enabled: ai.recon.enabled,
            criticPasses: ai.recon.critic_passes,
            census: ai.recon.census,
            maxLogicItems: ai.recon.max_logic_items,
          },
        }
      : {}),
    ...(flags.contextPack
      ? { context: loadContextPack(flags.contextPack) }
      : ai?.context
        ? { context: ai.context }
        : {}),
  };
}

export function currentUser(): string {
  try {
    return userInfo().username;
  } catch {
    return 'unknown';
  }
}
