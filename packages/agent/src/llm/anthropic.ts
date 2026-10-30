import Anthropic from '@anthropic-ai/sdk';
import {
  type CompletionRequest,
  type CompletionResult,
  type ContentBlock,
  type Effort,
  type LlmProvider,
  type Message,
  type ProviderCapabilities,
  RetryableTurnError,
  type StopReason,
} from './types';

/** Default model for security investigation roles (configurable per role, never hard-coded elsewhere). */
export const DEFAULT_ANTHROPIC_MODEL = 'claude-opus-5-5';
const FALLBACK_BETA = 'server-side-fallback-2026-07-01';

export interface AnthropicProviderOptions {
  /** Injected client (tests); otherwise credentials resolve from the environment or an `ant auth login` profile. */
  client?: Anthropic;
  model?: string;
  /** Claude Opus 5.5 defaults to medium; security reasoning is intelligence-sensitive, so default high. */
  effort?: Effort;
  /**
   * Server-side refusal fallback. "default" lets the API re-run a declined request on Anthropic's
   * recommended model for the refusal category; "off" surfaces refusals to the agent loop.
   */
  fallbacks?: 'default' | 'off';
  maxRetries?: number;
}

type BetaMessage = Anthropic.Beta.BetaMessage;
type BetaContentBlock = Anthropic.Beta.BetaContentBlock;
type BetaMessageParam = Anthropic.Beta.BetaMessageParam;
type BetaContentBlockParam = Anthropic.Beta.BetaContentBlockParam;

/**
 * Claude provider over the Messages API (ADR-020). Streams every request (long turns) and returns the
 * accumulated final message. Thinking is adaptive and controlled by effort; tool choice stays auto
 * because forced tool use is rejected by current models.
 */
export class AnthropicProvider implements LlmProvider {
  readonly id = 'anthropic';
  readonly model: string;
  private readonly client: Anthropic;
  private readonly effort: Effort;
  private readonly fallbacks: 'default' | 'off';

  constructor(options: AnthropicProviderOptions = {}) {
    this.client = options.client ?? new Anthropic({ maxRetries: options.maxRetries ?? 2 });
    this.model = options.model ?? DEFAULT_ANTHROPIC_MODEL;
    this.effort = options.effort ?? 'high';
    this.fallbacks = options.fallbacks ?? 'default';
  }

  capabilities(): ProviderCapabilities {
    return { tools: true, thinking: true, promptCaching: true, refusalFallback: this.fallbacks === 'default' };
  }

  async complete(
    request: CompletionRequest,
    options: { signal?: AbortSignal; onText?: (delta: string) => void } = {},
  ): Promise<CompletionResult> {
    const stream = this.client.beta.messages.stream(
      {
        model: this.model,
        max_tokens: request.maxTokens,
        // Stable prefix first: tools, then the frozen system prompt carrying the cache breakpoint.
        system: [{ type: 'text', text: request.system, cache_control: { type: 'ephemeral' } }],
        tools: request.tools.map((tool) => ({
          name: tool.name,
          description: tool.description,
          input_schema: tool.inputSchema as Anthropic.Beta.BetaTool.InputSchema,
          ...(tool.eagerInput === false ? {} : { eager_input_streaming: true }),
        })),
        messages: request.messages.map(toParam),
        thinking: { type: 'adaptive' },
        output_config: { effort: request.effort ?? this.effort },
        ...(this.fallbacks === 'default' ? { betas: [FALLBACK_BETA], fallbacks: 'default' as const } : {}),
      },
      { ...(options.signal ? { signal: options.signal } : {}) },
    );
    if (options.onText) stream.on('text', options.onText);
    let message: BetaMessage;
    try {
      message = await stream.finalMessage();
    } catch (err) {
      if (err instanceof Anthropic.APIError || options.signal?.aborted) throw err;
      // With eager input streaming a tool input that is not parseable JSON rejects the stream.
      throw new RetryableTurnError(err instanceof Error ? err.message : String(err));
    }
    return fromMessage(message);
  }
}

export function toParam(message: Message): BetaMessageParam {
  const content: BetaContentBlockParam[] = [];
  for (const block of message.content) {
    if (block.type === 'text') content.push({ type: 'text', text: block.text });
    else if (block.type === 'tool_use')
      content.push({ type: 'tool_use', id: block.id, name: block.name, input: block.input });
    else if (block.type === 'tool_result')
      content.push({
        type: 'tool_result',
        tool_use_id: block.toolUseId,
        content: block.content,
        ...(block.isError ? { is_error: true } : {}),
      });
    else if (block.provider === 'anthropic') content.push(block.block as BetaContentBlockParam);
  }
  return { role: message.role, content };
}

/**
 * Maps a response to neutral blocks. After a mid-output fallback, thinking/tool_use and other
 * model-internal blocks before the last `fallback` marker belong to the declined attempt: they are
 * neither executed nor replayed; text before the marker is kept.
 */
export function fromMessage(message: BetaMessage): CompletionResult {
  const blocks = message.content as BetaContentBlock[];
  const boundary = blocks.map((b) => b.type).lastIndexOf('fallback');
  const content: ContentBlock[] = [];
  const fallbacks: CompletionResult['fallbacks'] = [];
  blocks.forEach((block, index) => {
    if (block.type === 'fallback') {
      fallbacks.push({ from: block.from.model, to: block.to.model });
      return;
    }
    if (index < boundary && block.type !== 'text') return;
    if (block.type === 'text') content.push({ type: 'text', text: block.text });
    else if (block.type === 'tool_use')
      content.push({ type: 'tool_use', id: block.id, name: block.name, input: block.input });
    else content.push({ type: 'opaque', provider: 'anthropic', block });
  });
  const details = message.stop_details;
  return {
    content,
    stopReason: mapStop(message.stop_reason),
    usage: {
      inputTokens: message.usage.input_tokens,
      outputTokens: message.usage.output_tokens,
      cacheReadTokens: message.usage.cache_read_input_tokens ?? 0,
      cacheWriteTokens: message.usage.cache_creation_input_tokens ?? 0,
    },
    model: message.model,
    ...(message.stop_reason === 'refusal'
      ? {
          refusal: {
            ...(details?.category ? { category: details.category } : {}),
            ...(details?.explanation ? { explanation: details.explanation } : {}),
          },
        }
      : {}),
    fallbacks,
  };
}

function mapStop(reason: string | null): StopReason {
  switch (reason) {
    case 'end_turn':
    case 'tool_use':
    case 'max_tokens':
    case 'pause_turn':
    case 'refusal':
      return reason;
    default:
      return 'other';
  }
}
