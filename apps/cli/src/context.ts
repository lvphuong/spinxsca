import { userInfo } from 'node:os';
import type { AiExplainOptions } from './ai';
import { type LoadedConfig, loadConfig } from './config';
import { type Engine, openEngine } from './engine';
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
}

/** Opens the engine for a command and always closes it. */
export async function withEngine<T>(
  path: string | undefined,
  options: CommonOptions & { aiConfig?: AiExplainOptions },
  fn: (engine: Engine, loaded: LoadedConfig) => Promise<T>,
): Promise<T> {
  const loaded = loadConfig(options.config);
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
): (AiExplainOptions & { level: 'explain' | 'standard'; maxCostUsd: number; maxFindings: number }) | null {
  const ai = loaded.config.ai;
  const level = flags.ai ?? ai?.level ?? 'off';
  if (!['off', 'explain', 'standard'].includes(level)) {
    throw new CliError(`unknown --ai level "${level}" (expected off, explain or standard)`);
  }
  if (level === 'off' && !force) return null;
  if (ai && ai.send_source_snippets === false) {
    throw new CliError('AI is disabled for this project: ai.send_source_snippets is false in the configuration');
  }
  const provider = (flags.aiProvider ?? ai?.provider ?? 'anthropic') as AiExplainOptions['provider'];
  if (!['anthropic', 'openai-compatible', 'scripted'].includes(provider))
    throw new CliError(`unknown AI provider "${provider}"`);
  const allowed = ai?.data_policy?.allowed_providers;
  if (allowed && !allowed.includes(provider)) {
    throw new CliError(
      `AI provider "${provider}" is not allowed by ai.data_policy.allowed_providers (${allowed.join(', ')})`,
    );
  }
  const maxCost = flags.maxCost !== undefined ? Number(flags.maxCost) : (ai?.max_cost_usd_per_scan ?? 5);
  if (!Number.isFinite(maxCost) || maxCost <= 0) throw new CliError('--max-cost must be a positive number of USD');
  return {
    level: level === 'standard' ? 'standard' : 'explain',
    provider,
    ...((flags.model ?? ai?.model) ? { model: (flags.model ?? ai?.model) as string } : {}),
    ...(ai?.base_url ? { baseUrl: ai.base_url } : {}),
    ...(ai?.api_key_env ? { apiKeyEnv: ai.api_key_env } : {}),
    ...(ai?.data_policy?.exclude_paths.length ? { excludePaths: ai.data_policy.exclude_paths } : {}),
    effort: ai?.effort ?? 'high',
    refusalFallback: ai?.refusal_fallback ?? 'default',
    maxCostUsdPerFinding: maxCost,
    maxCostUsd: maxCost,
    maxFindings: ai?.max_findings ?? 20,
  };
}

export function currentUser(): string {
  try {
    return userInfo().username;
  } catch {
    return 'unknown';
  }
}
