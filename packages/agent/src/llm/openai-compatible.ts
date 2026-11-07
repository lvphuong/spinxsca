import { capabilitiesOf, type ModelProfile, type ProfileOverrides, resolveProfile } from './catalog';
import { repairJson } from './json-repair';
import { parseToolCalls, TOOL_CALL_OPEN } from './prompted-tools';
import {
  type CompletionRequest,
  type CompletionResult,
  type ContentBlock,
  isContextLengthError,
  type LlmProvider,
  type ProviderCapabilities,
  parseContextGap,
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
  /** Overrides on the catalog profile (context window, max output, tool mode, …). */
  profile?: ProfileOverrides;
  /** Server-sent events instead of one response (long local generations stay visible). */
  stream?: boolean;
  /** Sampling temperature; defaults to 0 for local-tier models, otherwise the server default. */
  temperature?: number;
  /** Default false: local models interleave several calls badly and the loop handles one at a time. */
  parallelToolCalls?: boolean;
}

type ChatMessage =
  | { role: 'system' | 'user'; content: string }
  | {
      role: 'assistant';
      content: string | null;
      tool_calls?: Array<{ id: string; type: 'function'; function: { name: string; arguments: string } }>;
    }
  | { role: 'tool'; tool_call_id: string; content: string };

export interface ChatToolCall {
  id?: string;
  function?: { name?: string; arguments?: string };
}

export interface ChatResponse {
  model?: string;
  choices?: Array<{
    finish_reason?: string;
    message?: {
      content?: string | null;
      reasoning_content?: string | null;
      refusal?: string | null;
      tool_calls?: ChatToolCall[];
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
 * Chat Completions provider for self-hosted models (docs/architecture/06 section 3.4, ADR-054):
 * source excerpts stay inside the customer network. Hardened for local models: optional streaming,
 * temperature, one tool call per turn, JSON schema response format, `<think>` stripping, missing
 * call ids, lenient argument repair, tool calls written as text, and context-length errors mapped
 * to a retryable kind the session can act on.
 */
export class OpenAICompatibleProvider implements LlmProvider {
  readonly id = 'openai-compatible';
  readonly model: string;
  private readonly http: typeof fetch;
  private readonly url: string;
  private readonly profile: ModelProfile;

  constructor(private readonly options: OpenAICompatibleOptions) {
    this.model = options.model;
    this.http = options.fetch ?? fetch;
    this.url = `${options.baseUrl.replace(/\/+$/, '')}/chat/completions`;
    this.profile = resolveProfile(options.model, options.profile ?? {});
  }

  capabilities(): ProviderCapabilities {
    return { ...capabilitiesOf(this.profile), thinking: false, refusalFallback: false };
  }

  async complete(
    request: CompletionRequest,
    options: { signal?: AbortSignal; onText?: (delta: string) => void } = {},
  ): Promise<CompletionResult> {
    const temperature =
      request.temperature ?? this.options.temperature ?? (this.profile.tier === 'local' ? 0 : undefined);
    const stream = this.options.stream === true;
    const body = {
      model: this.model,
      max_tokens: request.maxTokens,
      messages: toChatMessages(request),
      ...(temperature !== undefined ? { temperature } : {}),
      ...(request.tools.length
        ? {
            tools: request.tools.map((t) => ({
              type: 'function',
              function: { name: t.name, description: t.description, parameters: t.inputSchema },
            })),
            tool_choice: request.toolChoice === 'required' ? 'required' : 'auto',
            parallel_tool_calls: this.options.parallelToolCalls ?? false,
          }
        : {}),
      ...(request.responseSchema && !request.tools.length && this.profile.jsonMode
        ? {
            response_format: {
              type: 'json_schema',
              json_schema: { name: 'result', schema: request.responseSchema, strict: false },
            },
          }
        : {}),
      ...(stream ? { stream: true, stream_options: { include_usage: true } } : {}),
    };
    const retries = this.options.maxRetries ?? 2;
    const known = new Set(request.tools.map((t) => t.name));
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
      if (!res.ok) {
        const text = (await res.text()).slice(0, 600);
        if (res.status === 400 && isContextLengthError(text))
          throw new RetryableTurnError(`${this.id} 400: ${text}`, 'context', { detail: parseContextGap(text) ?? {} });
        if (res.status === 429 || res.status >= 500)
          throw new RetryableTurnError(`${this.id} ${res.status}: ${text}`, 'transient');
        throw new Error(`${this.id} ${res.status}: ${text}`);
      }
      const response = stream ? await readStream(res, options.onText) : ((await res.json()) as ChatResponse);
      const result = fromChatResponse(response, this.model, known);
      if (!stream) for (const block of result.content) if (block.type === 'text') options.onText?.(block.text);
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

/** Removes `<think>…</think>` reasoning (and an unterminated `<think>` tail) from model text. */
export function stripReasoning(text: string): string {
  return text
    .replace(/<think>[\s\S]*?<\/think>/g, '')
    .replace(/<think>[\s\S]*$/, '')
    .trim();
}

/**
 * Maps a chat response to neutral blocks. `knownTools` enables parsing of tool calls the model wrote
 * as text instead of using the tool-call channel (common with small models).
 */
export function fromChatResponse(
  response: ChatResponse,
  requestedModel: string,
  knownTools: ReadonlySet<string> = new Set(),
): CompletionResult {
  const choice = response.choices?.[0];
  if (!choice?.message) throw new RetryableTurnError('response without a message');
  const content: ContentBlock[] = [];
  let text = stripReasoning(choice.message.content ?? '');
  const calls = choice.message.tool_calls ?? [];
  const toolUses: ContentBlock[] = [];
  calls.forEach((call, index) => {
    const raw = call.function?.arguments || '{}';
    let input: unknown;
    try {
      input = JSON.parse(raw);
    } catch {
      const repaired = repairJson(raw);
      if (!repaired)
        throw new RetryableTurnError(`tool call ${call.function?.name} has invalid JSON arguments`, 'parse', {
          rawText: `${TOOL_CALL_OPEN}{"name":"${call.function?.name ?? ''}","arguments":${raw}}`,
        });
      input = repaired.value;
    }
    toolUses.push({ type: 'tool_use', id: call.id || `call_${index}`, name: call.function?.name ?? '', input });
  });
  if (toolUses.length === 0 && knownTools.size && text.includes('"name"')) {
    const parsed = parseToolCalls(text, knownTools);
    if (parsed.calls.length && parsed.problems.length === 0) {
      text = parsed.text;
      for (const [i, c] of parsed.calls.entries())
        toolUses.push({ type: 'tool_use', id: `text_${i}`, name: c.name, input: c.input });
    }
  }
  if (text) content.push({ type: 'text', text });
  content.push(...toolUses);
  const finish = FINISH[choice.finish_reason ?? ''];
  const stopReason: StopReason =
    finish === 'max_tokens' ? 'max_tokens' : toolUses.length ? 'tool_use' : (finish ?? 'other');
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

interface StreamChunk {
  model?: string;
  choices?: Array<{
    finish_reason?: string | null;
    delta?: {
      content?: string | null;
      reasoning_content?: string | null;
      tool_calls?: Array<{ index?: number; id?: string; function?: { name?: string; arguments?: string } }>;
    };
  }>;
  usage?: ChatResponse['usage'];
}

/** Reassembles a Chat Completions SSE stream into one response. */
export async function readStream(res: Response, onText?: (delta: string) => void): Promise<ChatResponse> {
  const text = await res.text();
  const out: ChatResponse = { choices: [{ message: { content: '' } }] };
  const message = (out.choices as NonNullable<ChatResponse['choices']>)[0] as NonNullable<
    NonNullable<ChatResponse['choices']>[number]
  >;
  const calls = new Map<number, ChatToolCall & { function: { name?: string; arguments: string } }>();
  let content = '';
  let thinking = false;
  for (const line of text.split(/\r?\n/)) {
    if (!line.startsWith('data:')) continue;
    const data = line.slice(5).trim();
    if (!data || data === '[DONE]') continue;
    let chunk: StreamChunk;
    try {
      chunk = JSON.parse(data) as StreamChunk;
    } catch {
      continue;
    }
    if (chunk.model) out.model = chunk.model;
    if (chunk.usage) out.usage = chunk.usage;
    const choice = chunk.choices?.[0];
    if (!choice) continue;
    if (choice.finish_reason) message.finish_reason = choice.finish_reason;
    const delta = choice.delta ?? {};
    if (delta.content) {
      content += delta.content;
      if (delta.content.includes('<think>')) thinking = true;
      if (delta.content.includes('</think>')) thinking = false;
      else if (!thinking) onText?.(delta.content);
    }
    for (const call of delta.tool_calls ?? []) {
      const index = call.index ?? 0;
      const current = calls.get(index) ?? { function: { arguments: '' } };
      if (call.id) current.id = call.id;
      if (call.function?.name) current.function.name = call.function.name;
      if (call.function?.arguments) current.function.arguments += call.function.arguments;
      calls.set(index, current);
    }
  }
  message.message = {
    content,
    ...(calls.size ? { tool_calls: [...calls.entries()].sort(([a], [b]) => a - b).map(([, c]) => c) } : {}),
  };
  return out;
}
