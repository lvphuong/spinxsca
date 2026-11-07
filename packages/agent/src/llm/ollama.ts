import { capabilitiesOf, type ModelProfile, type ProfileOverrides, resolveProfile } from './catalog';
import { fromChatResponse, toChatMessages } from './openai-compatible';
import {
  type CompletionRequest,
  type CompletionResult,
  isContextLengthError,
  type LlmProvider,
  type ProviderCapabilities,
  parseContextGap,
  RetryableTurnError,
} from './types';

export interface OllamaProviderOptions {
  /** Server origin, e.g. http://localhost:11434 (a trailing /v1 is ignored). */
  baseUrl: string;
  model: string;
  /**
   * Context length the server loads the model with. Ollama's own default is small (a few thousand
   * tokens) and silently truncates, so one is always sent: this value, else the catalog window capped at 32k.
   */
  numCtx?: number;
  profile?: ProfileOverrides;
  temperature?: number;
  /** Let thinking models think (slower; the reasoning is dropped). Default false. */
  think?: boolean;
  keepAlive?: string;
  maxRetries?: number;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

interface OllamaResponse {
  model?: string;
  message?: {
    content?: string;
    thinking?: string;
    tool_calls?: Array<{ function?: { name?: string; arguments?: unknown } }>;
  };
  done_reason?: string;
  prompt_eval_count?: number;
  eval_count?: number;
  error?: string;
}

/**
 * Native Ollama chat adapter (ADR-054). Compared to Ollama's OpenAI-compatible endpoint it can set
 * `num_ctx` per request, ask for a JSON schema with `format`, switch thinking off, and report the
 * real prompt/eval token counts; tool-call arguments arrive as objects, so nothing needs parsing.
 */
export class OllamaProvider implements LlmProvider {
  readonly id = 'ollama';
  readonly model: string;
  private readonly http: typeof fetch;
  private readonly url: string;
  private readonly profile: ModelProfile;
  private readonly numCtx: number;

  constructor(private readonly options: OllamaProviderOptions) {
    this.model = options.model;
    this.http = options.fetch ?? fetch;
    this.url = `${options.baseUrl.replace(/\/+$/, '').replace(/\/v1$/, '')}/api/chat`;
    const profile = resolveProfile(options.model, options.profile ?? {});
    this.numCtx = options.numCtx ?? Math.min(profile.contextWindow, 32_768);
    this.profile = { ...profile, contextWindow: this.numCtx };
  }

  capabilities(): ProviderCapabilities {
    return { ...capabilitiesOf(this.profile), thinking: false, refusalFallback: false };
  }

  async complete(
    request: CompletionRequest,
    options: { signal?: AbortSignal; onText?: (delta: string) => void } = {},
  ): Promise<CompletionResult> {
    const messages = toChatMessages(request).map((m) => {
      if (m.role === 'assistant' && m.tool_calls)
        return {
          role: 'assistant',
          content: m.content ?? '',
          tool_calls: m.tool_calls.map((c) => ({
            function: { name: c.function.name, arguments: safeParse(c.function.arguments) },
          })),
        };
      if (m.role === 'tool') return { role: 'tool', content: m.content, tool_call_id: m.tool_call_id };
      return m;
    });
    const body = {
      model: this.model,
      messages,
      stream: false,
      think: this.options.think ?? false,
      keep_alive: this.options.keepAlive ?? '10m',
      options: {
        num_ctx: this.numCtx,
        temperature: request.temperature ?? this.options.temperature ?? 0,
        num_predict: request.maxTokens,
      },
      ...(request.tools.length
        ? {
            tools: request.tools.map((t) => ({
              type: 'function',
              function: { name: t.name, description: t.description, parameters: t.inputSchema },
            })),
          }
        : {}),
      ...(request.responseSchema && !request.tools.length ? { format: request.responseSchema } : {}),
    };
    const retries = this.options.maxRetries ?? 2;
    for (let attempt = 0; ; attempt++) {
      const signal = AbortSignal.any([
        AbortSignal.timeout(this.options.timeoutMs ?? 600_000),
        ...(options.signal ? [options.signal] : []),
      ]);
      const res = await this.http(this.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal,
      });
      if (res.status >= 500 && attempt < retries) {
        await new Promise((r) => setTimeout(r, 1000 * 2 ** attempt));
        continue;
      }
      const text = await res.text();
      let parsed: OllamaResponse;
      try {
        parsed = JSON.parse(text) as OllamaResponse;
      } catch {
        throw new RetryableTurnError(`${this.id} returned a non-JSON body: ${text.slice(0, 200)}`);
      }
      if (!res.ok || parsed.error) {
        const message = parsed.error ?? text.slice(0, 600);
        if (isContextLengthError(message))
          throw new RetryableTurnError(`${this.id}: ${message}`, 'context', { detail: parseContextGap(message) ?? {} });
        if (res.status >= 500) throw new RetryableTurnError(`${this.id} ${res.status}: ${message}`, 'transient');
        throw new Error(`${this.id} ${res.status}: ${message}`);
      }
      const known = new Set(request.tools.map((t) => t.name));
      const result = fromChatResponse(
        {
          model: parsed.model,
          choices: [
            {
              finish_reason: parsed.done_reason === 'length' ? 'length' : 'stop',
              message: {
                content: parsed.message?.content ?? '',
                tool_calls: (parsed.message?.tool_calls ?? []).map((c, i) => ({
                  id: `ollama_${i}`,
                  function: { name: c.function?.name, arguments: JSON.stringify(c.function?.arguments ?? {}) },
                })),
              },
            },
          ],
          usage: { prompt_tokens: parsed.prompt_eval_count ?? 0, completion_tokens: parsed.eval_count ?? 0 },
        },
        this.model,
        known,
      );
      for (const block of result.content) if (block.type === 'text') options.onText?.(block.text);
      return result;
    }
  }
}

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}
