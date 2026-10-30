/**
 * Provider-neutral message model (docs/architecture/03 section 7). Providers translate to and from
 * their wire formats; provider-specific blocks that must be replayed unchanged (for example thinking
 * blocks) travel as `opaque` blocks owned by that provider.
 */
export type Effort = 'low' | 'medium' | 'high' | 'xhigh' | 'max';

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
}

export interface LlmProvider {
  readonly id: string;
  readonly model: string;
  capabilities(): ProviderCapabilities;
  complete(
    request: CompletionRequest,
    options?: { signal?: AbortSignal; onText?: (delta: string) => void },
  ): Promise<CompletionResult>;
}

/** The provider could not parse a streamed tool input; the turn can be re-issued unchanged. */
export class RetryableTurnError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RetryableTurnError';
  }
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
