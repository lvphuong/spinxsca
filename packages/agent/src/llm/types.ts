/**
 * Provider-neutral message model (docs/architecture/03 section 7). Providers translate to and from
 * their wire formats; provider-specific blocks that must be replayed unchanged (for example thinking
 * blocks) travel as `opaque` blocks owned by that provider.
 */
import type { ToolMode } from './catalog';

export type Effort = 'low' | 'medium' | 'high' | 'xhigh' | 'max';
export type { ToolMode } from './catalog';

export type ContentBlock =
  | { type: 'text'; text: string }
  | { type: 'tool_use'; id: string; name: string; input: unknown }
  | { type: 'tool_result'; toolUseId: string; content: string; isError?: boolean }
  | { type: 'opaque'; provider: string; block: unknown };

export interface Message {
  role: 'user' | 'assistant';
  content: ContentBlock[];
}

export interface ToolSpec {
  name: string;
  description: string;
  /** JSON Schema for the tool input (type: object). */
  inputSchema: Record<string, unknown>;
  /**
   * Stream the input unbuffered (Anthropic `eager_input_streaming`; default true). Unbuffered input is
   * not validated server-side, so malformed JSON fails the whole turn instead of reaching the loop.
   */
  eagerInput?: boolean;
}

export interface CompletionRequest {
  system: string;
  messages: readonly Message[];
  tools: readonly ToolSpec[];
  maxTokens: number;
  effort?: Effort;
  /** `required` forces a tool call (providers that cannot force ignore it). */
  toolChoice?: 'auto' | 'required';
  /** JSON Schema the whole reply must match when no tools are offered (structured single-shot). */
  responseSchema?: Record<string, unknown>;
  temperature?: number;
  metadata: { role: string; scanId?: string };
}

export interface Usage {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
}

export type StopReason = 'end_turn' | 'tool_use' | 'max_tokens' | 'pause_turn' | 'refusal' | 'other';

export interface CompletionResult {
  content: ContentBlock[];
  stopReason: StopReason;
  usage: Usage;
  /** Model that produced the final content (differs from the requested model after a fallback). */
  model: string;
  refusal?: { category?: string; explanation?: string };
  /** Model switches that happened inside this request (server-side refusal fallback). */
  fallbacks: Array<{ from: string; to: string }>;
}

export interface ProviderCapabilities {
  tools: boolean;
  thinking: boolean;
  promptCaching: boolean;
  refusalFallback: boolean;
  /** Context window in tokens (ADR-053); the session sizes compaction and `max_tokens` from it. */
  maxContext: number;
  /** Largest per-response output the model accepts. */
  maxOutput: number;
  /** How tools reach the model: native tool calling, rendered into the prompt, or not at all. */
  toolMode: ToolMode;
}

export interface LlmProvider {
  readonly id: string;
  readonly model: string;
  capabilities(): ProviderCapabilities;
  complete(
    request: CompletionRequest,
    options?: { signal?: AbortSignal; onText?: (delta: string) => void },
  ): Promise<CompletionResult>;
  /** Exact token count when the provider offers one; the session falls back to an estimate. */
  countTokens?(request: Pick<CompletionRequest, 'system' | 'messages' | 'tools'>): Promise<number>;
}

/**
 * Why a turn failed in a way the session can act on: `transient` re-issues the request unchanged,
 * `parse` sends the model its unusable reply with a correction request, `context` shrinks the
 * outbound view and retries.
 */
export type TurnErrorKind = 'transient' | 'parse' | 'context';

export class RetryableTurnError extends Error {
  readonly kind: TurnErrorKind;
  /** The reply that could not be used (parse errors), shown back to the model. */
  readonly rawText?: string;
  /** Token gap reported by the provider (context errors). */
  readonly detail?: { actual?: number; limit?: number };

  constructor(
    message: string,
    kind: TurnErrorKind = 'transient',
    extra: { rawText?: string; detail?: { actual?: number; limit?: number } } = {},
  ) {
    super(message);
    this.name = 'RetryableTurnError';
    this.kind = kind;
    if (extra.rawText !== undefined) this.rawText = extra.rawText;
    if (extra.detail) this.detail = extra.detail;
  }
}

const CONTEXT_ERROR =
  /context[_ ]length[_ ]exceeded|maximum context length|prompt is too long|too many tokens|exceeds the (?:context|limit)|input length and `?max_tokens`? exceed|reduce the length of the messages/i;

/** True for provider error text that means the request did not fit the context window. */
export function isContextLengthError(text: string): boolean {
  return CONTEXT_ERROR.test(text);
}

/** `… 17000 tokens > 16000 maximum …` -> { actual: 17000, limit: 16000 } */
export function parseContextGap(text: string): { actual?: number; limit?: number } | undefined {
  const gap = /(\d[\d,]*)\s*tokens?\s*>\s*(\d[\d,]*)/i.exec(text);
  if (gap) return { actual: Number(gap[1]?.replace(/,/g, '')), limit: Number(gap[2]?.replace(/,/g, '')) };
  const openai = /maximum context length is (\d+) tokens.*?requested (\d+) tokens/is.exec(text);
  if (openai) return { limit: Number(openai[1]), actual: Number(openai[2]) };
  return undefined;
}

export const ZERO_USAGE: Usage = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };

export function addUsage(a: Usage, b: Usage): Usage {
  return {
    inputTokens: a.inputTokens + b.inputTokens,
    outputTokens: a.outputTokens + b.outputTokens,
    cacheReadTokens: a.cacheReadTokens + b.cacheReadTokens,
    cacheWriteTokens: a.cacheWriteTokens + b.cacheWriteTokens,
  };
}
