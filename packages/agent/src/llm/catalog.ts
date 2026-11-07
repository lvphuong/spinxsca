/**
 * Model catalog (ADR-053). Every model the agent may talk to is described by a profile: how much
 * context it holds, how much it can emit per turn, whether it calls tools natively or has to be
 * prompted, and what it costs. Profiles come from this built-in table, from endpoint detection
 * (`detect.ts`) and from operator overrides (`ai.models.<alias>`); unknown models get a conservative
 * profile instead of a guess that overflows a small window.
 */

/** How a model is asked to call tools. */
export type ToolMode = 'native' | 'prompted' | 'none';
/** Routing tier a model is meant for: frontier reasoning, cheap/fast helper, or self-hosted. */
export type ModelTier = 'deep' | 'fast' | 'local';

/** USD per million tokens. Cache writes are 1.25x input. */
export interface ModelPrice {
  input: number;
  output: number;
  cacheRead: number;
}

export interface ModelProfile {
  /** The model id the profile was resolved for. */
  id: string;
  /** Total context window in tokens (input + output). */
  contextWindow: number;
  /** Largest `max_tokens` the model accepts for one response. */
  maxOutput: number;
  toolMode: ToolMode;
  /** Supports a JSON schema response format (`response_format` / Ollama `format`). */
  jsonMode: boolean;
  /** Emits `<think>…</think>` or `reasoning_content` that must be stripped. */
  reasoningTags: boolean;
  tier: ModelTier;
  promptCaching: boolean;
  /** Absent for models without a known price: cost is then unknown, never guessed. */
  pricing?: ModelPrice;
  notes?: string;
}

interface CatalogEntry extends Omit<ModelProfile, 'id'> {
  /** Catalog key used in reports and tests. */
  key: string;
  match: RegExp;
}

const CLAUDE = {
  contextWindow: 200_000,
  maxOutput: 32_000,
  toolMode: 'native' as const,
  jsonMode: false,
  reasoningTags: false,
  tier: 'deep' as const,
  promptCaching: true,
};
const LOCAL = { jsonMode: true, reasoningTags: false, tier: 'local' as const, promptCaching: false };

/** Source for Claude prices: Anthropic pricing, 2026-09. Exact ids keep `costOf` behaviour unchanged. */
const CLAUDE_PRICES: Record<string, ModelPrice> = {
  'claude-fable-5-1': { input: 10, output: 50, cacheRead: 0.25 },
  'claude-fable-5': { input: 10, output: 50, cacheRead: 1 },
  'claude-opus-5-5': { input: 4, output: 20, cacheRead: 0.2 },
  'claude-opus-5': { input: 5, output: 25, cacheRead: 0.5 },
  'claude-opus-4-8': { input: 5, output: 25, cacheRead: 0.5 },
  'claude-opus-4-7': { input: 5, output: 25, cacheRead: 0.5 },
  'claude-sonnet-5-5': { input: 2, output: 10, cacheRead: 0.2 },
  'claude-sonnet-5': { input: 2, output: 10, cacheRead: 0.2 },
  'claude-haiku-4-5': { input: 1, output: 5, cacheRead: 0.1 },
};

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export const BUILTIN_PROFILES: readonly CatalogEntry[] = [
  ...Object.entries(CLAUDE_PRICES).map(([id, pricing]) => ({
    key: id,
    match: new RegExp(`^${escapeRegExp(id)}(-\\d{8})?$`),
    ...CLAUDE,
    ...(id.includes('haiku') ? { tier: 'fast' as const, maxOutput: 16_000 } : {}),
    pricing,
  })),
  { key: 'claude', match: /^claude-/i, ...CLAUDE, notes: 'unpriced Claude model' },
  {
    key: 'scripted',
    match: /^scripted/,
    ...CLAUDE,
    promptCaching: false,
    maxOutput: 32_000,
    contextWindow: 1_000_000,
    pricing: { input: 0, output: 0, cacheRead: 0 },
  },
  {
    key: 'gpt-5',
    match: /^gpt-5/i,
    contextWindow: 400_000,
    maxOutput: 32_000,
    toolMode: 'native',
    jsonMode: true,
    reasoningTags: false,
    tier: 'deep',
    promptCaching: true,
  },
  {
    key: 'gpt-4.1',
    match: /^gpt-4\.1/i,
    contextWindow: 1_000_000,
    maxOutput: 32_000,
    toolMode: 'native',
    jsonMode: true,
    reasoningTags: false,
    tier: 'deep',
    promptCaching: true,
  },
  {
    key: 'gpt-4o',
    match: /^gpt-4o/i,
    contextWindow: 128_000,
    maxOutput: 16_000,
    toolMode: 'native',
    jsonMode: true,
    reasoningTags: false,
    tier: 'deep',
    promptCaching: true,
  },
  {
    key: 'qwen3-coder',
    match: /qwen3[-_.]?coder/i,
    contextWindow: 131_072,
    maxOutput: 8_192,
    toolMode: 'native',
    ...LOCAL,
  },
  {
    key: 'qwen3',
    match: /qwen3/i,
    contextWindow: 32_768,
    maxOutput: 8_192,
    toolMode: 'native',
    ...LOCAL,
    reasoningTags: true,
  },
  {
    key: 'qwen2.5-coder',
    match: /qwen2[-_.]?5[-_.]?coder/i,
    contextWindow: 32_768,
    maxOutput: 8_192,
    toolMode: 'native',
    ...LOCAL,
    notes: 'Hermes-style tool calls; 128k only with YaRN',
  },
  { key: 'qwen2.5', match: /qwen2[-_.]?5/i, contextWindow: 32_768, maxOutput: 8_192, toolMode: 'native', ...LOCAL },
  {
    key: 'deepseek-r1',
    match: /deepseek[-_.]?r1/i,
    contextWindow: 131_072,
    maxOutput: 8_192,
    toolMode: 'prompted',
    ...LOCAL,
    reasoningTags: true,
  },
  { key: 'deepseek', match: /deepseek/i, contextWindow: 131_072, maxOutput: 8_192, toolMode: 'native', ...LOCAL },
  {
    key: 'llama3',
    match: /llama[-_ .]?3/i,
    contextWindow: 131_072,
    maxOutput: 4_096,
    toolMode: 'native',
    ...LOCAL,
    notes: 'tool calling is weak; prompted mode often works better',
  },
  { key: 'devstral', match: /devstral/i, contextWindow: 131_072, maxOutput: 8_192, toolMode: 'native', ...LOCAL },
  { key: 'codestral', match: /codestral/i, contextWindow: 256_000, maxOutput: 8_192, toolMode: 'native', ...LOCAL },
  { key: 'mistral', match: /mistral|mixtral/i, contextWindow: 131_072, maxOutput: 8_192, toolMode: 'native', ...LOCAL },
  {
    key: 'gemma3',
    match: /gemma[-_.]?3/i,
    contextWindow: 131_072,
    maxOutput: 8_192,
    toolMode: 'prompted',
    ...LOCAL,
    jsonMode: false,
  },
  { key: 'phi', match: /phi[-_.]?[34]/i, contextWindow: 131_072, maxOutput: 4_096, toolMode: 'prompted', ...LOCAL },
];

/**
 * Profile for a model nobody described: a small window and prompted tools, so a wrong guess costs
 * throughput rather than failed requests. Detection or `ai.models` overrides refine it.
 */
export const CONSERVATIVE_PROFILE: Omit<ModelProfile, 'id'> = {
  contextWindow: 32_768,
  maxOutput: 4_096,
  toolMode: 'prompted',
  jsonMode: false,
  reasoningTags: true,
  tier: 'local',
  promptCaching: false,
  notes: 'unknown model: conservative defaults',
};

/** Strips a provider prefix (`ollama/`, `openai/`) and a vendor path (`Qwen/`) before matching. */
function normalizeModelId(model: string): string {
  const slash = model.lastIndexOf('/');
  return slash >= 0 ? model.slice(slash + 1) : model;
}

/** Built-in profile for a model id, or undefined when nothing matches. */
export function lookupProfile(model: string): ModelProfile | undefined {
  const id = normalizeModelId(model);
  const entry = BUILTIN_PROFILES.find((e) => e.match.test(id)) ?? BUILTIN_PROFILES.find((e) => e.match.test(model));
  if (!entry) return undefined;
  const { match: _match, key: _key, ...profile } = entry;
  return { id: model, ...profile };
}

export type ProfileOverrides = Partial<Omit<ModelProfile, 'id'>>;

/** Built-in profile (or the conservative one) with defined override fields applied on top. */
export function resolveProfile(model: string, overrides: ProfileOverrides = {}): ModelProfile {
  const base = lookupProfile(model) ?? { id: model, ...CONSERVATIVE_PROFILE };
  const defined = Object.fromEntries(Object.entries(overrides).filter(([, v]) => v !== undefined));
  return { ...base, ...defined, id: model };
}

/** Price table entry for a model: exact catalog pricing, or an override; undefined when unknown. */
export function priceOf(model: string): ModelPrice | undefined {
  return lookupProfile(model)?.pricing;
}

/** Provider capabilities implied by a profile (the provider adds `thinking`/`refusalFallback`). */
export function capabilitiesOf(profile: ModelProfile): {
  tools: boolean;
  promptCaching: boolean;
  maxContext: number;
  maxOutput: number;
  toolMode: ToolMode;
} {
  return {
    tools: profile.toolMode !== 'none',
    promptCaching: profile.promptCaching,
    maxContext: profile.contextWindow,
    maxOutput: profile.maxOutput,
    toolMode: profile.toolMode,
  };
}

/** Capabilities of the scripted test doubles: a huge window so fixtures never compact by accident. */
export const SCRIPTED_CAPABILITIES = {
  tools: true,
  thinking: false,
  promptCaching: false,
  refusalFallback: false,
  maxContext: 1_000_000,
  maxOutput: 32_000,
  toolMode: 'native' as const,
};
