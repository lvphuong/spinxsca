import {
  type CompletionRequest,
  type CompletionResult,
  type ContentBlock,
  type LlmProvider,
  type ProviderCapabilities,
  RetryableTurnError,
  type StopReason,
} from './types';

export interface OpenAICompatibleOptions {
  /** Base URL of an OpenAI-compatible API, e.g. http://llm.internal:8000/v1 (vLLM, Ollama, LiteLLM, LM Studio). */
  baseUrl: string;
  model: string;
  apiKey?: string;
  maxRetries?: number;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

type ChatMessage =
  | { role: 'system' | 'user'; content: string }
  | {
      role: 'assistant';
      content: string | null;
      tool_calls?: Array<{ id: string; type: 'function'; function: { name: string; arguments: string } }>;
    }
  | { role: 'tool'; tool_call_id: string; content: string };

interface ChatResponse {
  model?: string;
  choices?: Array<{
    finish_reason?: string;
    message?: {
      content?: string | null;
      refusal?: string | null;
      tool_calls?: Array<{ id: string; function?: { name?: string; arguments?: string } }>;
    };
  }>;
  usage?: { prompt_tokens?: number; completion_tokens?: number; prompt_tokens_details?: { cached_tokens?: number } };
}

const FINISH: Record<string, StopReason> = {
  stop: 'end_turn',
  tool_calls: 'tool_use',
  function_call: 'tool_use',
  length: 'max_tokens',
  content_filter: 'refusal',
};

/**
 * Chat Completions provider for self-hosted models (docs/architecture/06 section 3.4): source excerpts
 * stay inside the customer network. Tool calling is required; models without it cannot submit
 * structured results and every run ends as FAILED, which the host reports.
 */
export class OpenAICompatibleProvider implements LlmProvider {
  readonly id = 'openai-compatible';
  readonly model: string;
  private readonly http: typeof fetch;
  private readonly url: string;

  constructor(private readonly options: OpenAICompatibleOptions) {
    this.model = options.model;
    this.http = options.fetch ?? fetch;
    this.url = `${options.baseUrl.replace(/\/+$/, '')}/chat/completions`;
  }

  capabilities(): ProviderCapabilities {
    return { tools: true, thinking: false, promptCaching: false, refusalFallback: false };
  }

  async complete(
    request: CompletionRequest,
    options: { signal?: AbortSignal; onText?: (delta: string) => void } = {},
  ): Promise<CompletionResult> {
    const body = {
      model: this.model,
      max_tokens: request.maxTokens,
      messages: toChatMessages(request),
      ...(request.tools.length
        ? {
            tools: request.tools.map((t) => ({
              type: 'function',
              function: { name: t.name, description: t.description, parameters: t.inputSchema },
            })),
            tool_choice: 'auto',
          }
        : {}),
    };
    const retries = this.options.maxRetries ?? 2;
    for (let attempt = 0; ; attempt++) {
      const signal = AbortSignal.any([
        AbortSignal.timeout(this.options.timeoutMs ?? 300_000),
        ...(options.signal ? [options.signal] : []),
      ]);
      const res = await this.http(this.url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(this.options.apiKey ? { authorization: `Bearer ${this.options.apiKey}` } : {}),
        },
        body: JSON.stringify(body),
        signal,
      });
      if ((res.status === 429 || res.status >= 500) && attempt < retries) {
        await new Promise((r) => setTimeout(r, 1000 * 2 ** attempt));
        continue;
      }
      if (!res.ok) throw new Error(`${this.id} ${res.status}: ${(await res.text()).slice(0, 300)}`);
      const result = fromChatResponse((await res.json()) as ChatResponse, this.model);
      for (const block of result.content) if (block.type === 'text') options.onText?.(block.text);
      return result;
    }
  }
}

export function toChatMessages(request: CompletionRequest): ChatMessage[] {
  const out: ChatMessage[] = [{ role: 'system', content: request.system }];
  for (const message of request.messages) {
    if (message.role === 'assistant') {
      const text = message.content.flatMap((b) => (b.type === 'text' ? [b.text] : [])).join('');
      const calls = message.content.flatMap((b) =>
        b.type === 'tool_use'
          ? [
              {
                id: b.id,
                type: 'function' as const,
                function: { name: b.name, arguments: JSON.stringify(b.input ?? {}) },
              },
            ]
          : [],
      );
      out.push({ role: 'assistant', content: text || null, ...(calls.length ? { tool_calls: calls } : {}) });
      continue;
    }
    // Tool results must directly follow the assistant message that requested them.
    for (const b of message.content) {
      if (b.type === 'tool_result')
        out.push({ role: 'tool', tool_call_id: b.toolUseId, content: b.isError ? `ERROR: ${b.content}` : b.content });
    }
    const text = message.content.flatMap((b) => (b.type === 'text' ? [b.text] : [])).join('\n');
    if (text) out.push({ role: 'user', content: text });
  }
  return out;
}

export function fromChatResponse(response: ChatResponse, requestedModel: string): CompletionResult {
  const choice = response.choices?.[0];
  if (!choice?.message) throw new RetryableTurnError('response without a message');
  const content: ContentBlock[] = [];
  if (choice.message.content) content.push({ type: 'text', text: choice.message.content });
  for (const call of choice.message.tool_calls ?? []) {
    let input: unknown;
    try {
      input = JSON.parse(call.function?.arguments || '{}');
    } catch {
      throw new RetryableTurnError(`tool call ${call.function?.name} has invalid JSON arguments`);
    }
    content.push({ type: 'tool_use', id: call.id, name: call.function?.name ?? '', input });
  }
  const stopReason: StopReason = choice.message.tool_calls?.length
    ? 'tool_use'
    : (FINISH[choice.finish_reason ?? ''] ?? 'other');
  const cached = response.usage?.prompt_tokens_details?.cached_tokens ?? 0;
  return {
    content,
    stopReason,
    usage: {
      inputTokens: Math.max(0, (response.usage?.prompt_tokens ?? 0) - cached),
      outputTokens: response.usage?.completion_tokens ?? 0,
      cacheReadTokens: cached,
      cacheWriteTokens: 0,
    },
    model: response.model ?? requestedModel,
    ...(choice.message.refusal ? { refusal: { explanation: choice.message.refusal } } : {}),
    fallbacks: [],
  };
}
