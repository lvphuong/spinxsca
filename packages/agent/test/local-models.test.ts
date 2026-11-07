import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  buildRegistry,
  type CompletionRequest,
  fromChatResponse,
  OllamaProvider,
  OpenAICompatibleProvider,
  parseToolCalls,
  RateLimiter,
  RetryableTurnError,
  readStream,
  renderToolsForPrompt,
  repairJson,
  runStructured,
  ScriptedProvider,
  stripReasoning,
  withPromptedTools,
  withRateLimit,
} from '../src/index';

const tools = [
  {
    name: 'read_file',
    description: 'Read a file.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string', description: 'repo path' }, start_line: { type: 'integer' } },
      required: ['path'],
    },
  },
  {
    name: 'submit_result',
    description: 'Submit.',
    inputSchema: {
      type: 'object',
      properties: { findings: { type: 'array', items: { type: 'object', properties: { title: { type: 'string' } } } } },
      required: ['findings'],
    },
  },
];
const base = (over: Partial<CompletionRequest> = {}): CompletionRequest => ({
  system: 'sys',
  messages: [{ role: 'user', content: [{ type: 'text', text: 'go' }] }],
  tools,
  maxTokens: 100,
  metadata: { role: 'test' },
  ...over,
});
const json = (body: unknown, status = 200) =>
  new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });

describe('JSON repair', () => {
  it('passes valid JSON through unchanged', () => {
    expect(repairJson('{"a": 1}')).toEqual({ value: { a: 1 }, repaired: false });
  });
  it('repairs fences, prose, trailing commas, single quotes, bare keys and Python literals', () => {
    expect(repairJson('Sure! Here it is:\n```json\n{"a": [1, 2,], "b": {"c": 3,},}\n```')?.value).toEqual({
      a: [1, 2],
      b: { c: 3 },
    });
    expect(repairJson("{'name': 'read_file', 'arguments': {'path': \"it's\"}}")?.value).toEqual({
      name: 'read_file',
      arguments: { path: "it's" },
    });
    expect(repairJson('{name: "x", ok: True, none: None, no: False}')?.value).toEqual({
      name: 'x',
      ok: true,
      none: null,
      no: false,
    });
  });
  it('closes truncated documents and gives up on garbage', () => {
    expect(repairJson('{"findings": [{"title": "a"}, {"title": "b')?.value).toEqual({
      findings: [{ title: 'a' }, { title: 'b' }],
    });
    expect(repairJson('{"a": "unterminated')?.value).toEqual({ a: 'unterminated' });
    expect(repairJson('not json at all')).toBeUndefined();
    expect(repairJson('{bad')).toBeUndefined();
  });
});

describe('prompted tool mode', () => {
  it('renders every tool once and stays compact', () => {
    const text = renderToolsForPrompt(tools);
    expect(text).toContain('### read_file');
    expect(text).toContain('"path": string /* repo path */');
    expect(text).toContain('"start_line"?: integer');
    expect(text).toContain('{ "title"?: string }[]');
    expect(text.match(/### /g)).toHaveLength(2);
    const verbose = [{ ...tools[0], description: 'x'.repeat(5_000) }] as typeof tools;
    expect(renderToolsForPrompt(verbose).length).toBeLessThan(3_100);
    expect(renderToolsForPrompt(verbose)).toContain('…');
  });

  it('parses Hermes blocks, fenced JSON and bare objects, and reports unknown tools', () => {
    const known = new Set(['read_file', 'submit_result']);
    const hermes = parseToolCalls(
      'I will read it.\n<tool_call>{"name":"read_file","arguments":{"path":"a.ts",}}</tool_call>',
      known,
    );
    expect(hermes.calls).toEqual([
      { name: 'read_file', input: { path: 'a.ts' }, raw: '{"name":"read_file","arguments":{"path":"a.ts",}}' },
    ]);
    expect(hermes.text).toBe('I will read it.');
    const fenced = parseToolCalls(
      '```json\n{"name": "read_file", "arguments": "{\\"path\\": \\"b.ts\\"}"}\n```',
      known,
    );
    expect(fenced.calls[0]).toMatchObject({ name: 'read_file', input: { path: 'b.ts' } });
    const bare = parseToolCalls('{"name": "submit_result", "arguments": {"findings": []}}', known);
    expect(bare.calls[0]).toMatchObject({ name: 'submit_result', input: { findings: [] } });
    const unknown = parseToolCalls('<tool_call>{"name":"rm_rf","arguments":{}}</tool_call>', known);
    expect(unknown.calls).toHaveLength(0);
    expect(unknown.problems[0]).toContain('unknown tool "rm_rf"');
    expect(parseToolCalls('plain prose', known)).toEqual({ calls: [], text: 'plain prose', problems: [] });
  });

  it('round-trips through the decorator: tools in the prompt, calls parsed, results rendered as text', async () => {
    const inner = new ScriptedProvider([
      {
        content: [
          { type: 'text', text: 'Reading.\n<tool_call>{"name":"read_file","arguments":{"path":"a.ts"}}</tool_call>' },
        ],
      },
      { content: [{ type: 'text', text: 'done, no call' }] },
    ]);
    const provider = withPromptedTools(inner);
    expect(provider.capabilities().toolMode).toBe('prompted');
    const first = await provider.complete(base());
    expect(first.stopReason).toBe('tool_use');
    expect(first.content).toEqual([
      { type: 'text', text: 'Reading.' },
      { type: 'tool_use', id: 'pt_1_0', name: 'read_file', input: { path: 'a.ts' } },
    ]);
    const sent = inner.requests[0] as CompletionRequest;
    expect(sent.tools).toEqual([]);
    expect(sent.system).toContain('### read_file');
    const second = await provider.complete(
      base({
        messages: [
          ...base().messages,
          { role: 'assistant', content: first.content },
          { role: 'user', content: [{ type: 'tool_result', toolUseId: 'pt_1_0', content: 'line 1' }] },
        ],
      }),
    );
    expect(second.stopReason).toBe('end_turn');
    const replay = inner.requests[1] as CompletionRequest;
    const lastMessage = replay.messages.at(-1) as (typeof replay.messages)[number];
    const lastText = (lastMessage.content[0] as { text: string }).text;
    expect(lastText).toContain('<tool_result name="read_file">');
    expect(lastText).toContain('line 1');
    const assistant = replay.messages[1] as (typeof replay.messages)[number];
    expect((assistant.content[0] as { text: string }).text).toContain('<tool_call>');
    await expect(
      withPromptedTools(new ScriptedProvider([{ content: [{ type: 'text', text: 'no call' }] }])).complete(
        base({ toolChoice: 'required' }),
      ),
    ).rejects.toMatchObject({ kind: 'parse', rawText: 'no call' });
  });
});

describe('OpenAI-compatible hardening', () => {
  it('strips reasoning, synthesizes ids, parses text tool calls and maps length', () => {
    expect(stripReasoning('<think>hmm</think>answer')).toBe('answer');
    expect(stripReasoning('<think>never closed')).toBe('');
    const r = fromChatResponse(
      {
        choices: [
          {
            finish_reason: 'tool_calls',
            message: {
              content: '<think>plan</think>',
              reasoning_content: 'ignored',
              tool_calls: [{ function: { name: 'read_file', arguments: '{"path": "a.ts",}' } }],
            },
          },
        ],
      },
      'm',
    );
    expect(r.content).toEqual([{ type: 'tool_use', id: 'call_0', name: 'read_file', input: { path: 'a.ts' } }]);
    const text = fromChatResponse(
      {
        choices: [
          {
            finish_reason: 'stop',
            message: {
              content: 'Let me read.\n<tool_call>{"name":"read_file","arguments":{"path":"z.ts"}}</tool_call>',
            },
          },
        ],
      },
      'm',
      new Set(['read_file']),
    );
    expect(text.stopReason).toBe('tool_use');
    expect(text.content).toEqual([
      { type: 'text', text: 'Let me read.' },
      { type: 'tool_use', id: 'text_0', name: 'read_file', input: { path: 'z.ts' } },
    ]);
    expect(
      fromChatResponse(
        {
          choices: [
            {
              finish_reason: 'length',
              message: { tool_calls: [{ id: 'a', function: { name: 'f', arguments: '{}' } }] },
            },
          ],
        },
        'm',
      ).stopReason,
    ).toBe('max_tokens');
    try {
      fromChatResponse(
        { choices: [{ message: { tool_calls: [{ id: 't', function: { name: 'f', arguments: '{bad' } }] } }] },
        'm',
      );
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(RetryableTurnError);
      expect((err as RetryableTurnError).kind).toBe('parse');
      expect((err as RetryableTurnError).rawText).toContain('{bad');
    }
  });

  it('sends local-model flags and maps context-length errors', async () => {
    const bodies: Array<Record<string, unknown>> = [];
    let status = 200;
    const fetchMock = (async (_url: string, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)));
      if (status === 400)
        return json(
          {
            error: {
              message: "This model's maximum context length is 16000 tokens. However, you requested 17000 tokens",
            },
          },
          400,
        );
      return json({ choices: [{ finish_reason: 'stop', message: { content: 'ok' } }] });
    }) as unknown as typeof fetch;
    const provider = new OpenAICompatibleProvider({
      baseUrl: 'http://llm/v1',
      model: 'qwen2.5-coder:14b',
      fetch: fetchMock,
      maxRetries: 0,
    });
    expect(provider.capabilities()).toMatchObject({ maxContext: 32_768, maxOutput: 8_192, toolMode: 'native' });
    await provider.complete(base({ toolChoice: 'required' }));
    expect(bodies[0]).toMatchObject({ temperature: 0, tool_choice: 'required', parallel_tool_calls: false });
    await provider.complete(base({ tools: [], responseSchema: { type: 'object' } }));
    expect(bodies[1]).toMatchObject({ response_format: { type: 'json_schema' } });
    expect(bodies[1]).not.toHaveProperty('tools');
    status = 400;
    const err = await provider.complete(base()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RetryableTurnError);
    expect((err as RetryableTurnError).kind).toBe('context');
    expect((err as RetryableTurnError).detail).toEqual({ limit: 16_000, actual: 17_000 });
  });

  it('reassembles a streamed tool call', async () => {
    const chunks = [
      { model: 'm', choices: [{ delta: { content: '<think>x' } }] },
      { choices: [{ delta: { content: '</think>Hi' } }] },
      {
        choices: [
          { delta: { tool_calls: [{ index: 0, id: 'c1', function: { name: 'read_file', arguments: '{"pa' } }] } },
        ],
      },
      { choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: 'th":"a.ts"}' } }] } }] },
      { choices: [{ delta: {}, finish_reason: 'tool_calls' }], usage: { prompt_tokens: 7, completion_tokens: 3 } },
    ];
    const sse = `${chunks.map((c) => `data: ${JSON.stringify(c)}`).join('\n\n')}\n\ndata: [DONE]\n`;
    const seen: string[] = [];
    const response = await readStream(new Response(sse), (d) => seen.push(d));
    const result = fromChatResponse(response, 'm');
    expect(result.content).toEqual([
      { type: 'text', text: 'Hi' },
      { type: 'tool_use', id: 'c1', name: 'read_file', input: { path: 'a.ts' } },
    ]);
    expect(result.usage).toMatchObject({ inputTokens: 7, outputTokens: 3 });
    expect(seen).toEqual([]);
    const streaming = new OpenAICompatibleProvider({
      baseUrl: 'http://llm/v1',
      model: 'm',
      stream: true,
      fetch: (async (_u: string, init?: RequestInit) => {
        expect(JSON.parse(String(init?.body))).toMatchObject({ stream: true, stream_options: { include_usage: true } });
        return new Response(sse);
      }) as unknown as typeof fetch,
    });
    expect((await streaming.complete(base())).stopReason).toBe('tool_use');
  });
});

describe('Ollama adapter', () => {
  it('sends num_ctx, format and object tool arguments, and maps done_reason', async () => {
    const bodies: Array<Record<string, unknown>> = [];
    const fetchMock = (async (url: string, init?: RequestInit) => {
      expect(url).toBe('http://localhost:11434/api/chat');
      const body = JSON.parse(String(init?.body));
      bodies.push(body);
      if (body.format)
        return json({
          model: 'qwen2.5-coder:14b',
          message: { content: '{"verdict":"ok"}' },
          done_reason: 'stop',
          prompt_eval_count: 5,
          eval_count: 2,
        });
      return json({
        model: 'qwen2.5-coder:14b',
        message: { content: '', tool_calls: [{ function: { name: 'read_file', arguments: { path: 'a.ts' } } }] },
        done_reason: body.options.num_predict === 1 ? 'length' : 'stop',
        prompt_eval_count: 11,
        eval_count: 4,
      });
    }) as unknown as typeof fetch;
    const provider = new OllamaProvider({
      baseUrl: 'http://localhost:11434/v1',
      model: 'qwen2.5-coder:14b',
      numCtx: 16_384,
      fetch: fetchMock,
    });
    expect(provider.capabilities().maxContext).toBe(16_384);
    const r = await provider.complete(base());
    expect(bodies[0]).toMatchObject({ think: false, options: { num_ctx: 16_384, temperature: 0, num_predict: 100 } });
    expect(r.content).toEqual([{ type: 'tool_use', id: 'ollama_0', name: 'read_file', input: { path: 'a.ts' } }]);
    expect(r.usage).toMatchObject({ inputTokens: 11, outputTokens: 4 });
    await provider.complete(base({ tools: [], responseSchema: { type: 'object' } }));
    expect(bodies[1]).toMatchObject({ format: { type: 'object' } });
    expect((await provider.complete(base({ maxTokens: 1 }))).stopReason).toBe('max_tokens');
  });
});

describe('structured single-shot', () => {
  const Verdict = z.strictObject({ verdict: z.enum(['ok', 'bad']), reason: z.string().min(1) });
  it('repairs malformed JSON, feeds back validation problems and fails after the last attempt', async () => {
    const provider = new ScriptedProvider([
      { content: [{ type: 'text', text: 'Here:\n```json\n{"verdict": "ok", "reason": "fine",}\n```' }] },
    ]);
    const ok = await runStructured({ provider, role: 'r', system: 's', prompt: 'p', schema: Verdict });
    expect(ok.status).toBe('COMPLETED');
    expect(ok.output).toEqual({ verdict: 'ok', reason: 'fine' });
    expect((provider.requests[0] as CompletionRequest).responseSchema).toMatchObject({ type: 'object' });
    expect((provider.requests[0] as CompletionRequest).tools).toEqual([]);

    const corrected = new ScriptedProvider([
      { content: [{ type: 'text', text: '{"verdict": "bad", "reason": "x"}' }] },
      { content: [{ type: 'text', text: '{"verdict": "ok", "reason": "x"}' }] },
    ]);
    const second = await runStructured({
      provider: corrected,
      role: 'r',
      system: 's',
      prompt: 'p',
      schema: Verdict,
      validate: (v) => (v.verdict === 'ok' ? [] : ['verdict must be ok']),
    });
    expect(second.status).toBe('COMPLETED');
    const retry = corrected.requests[1] as CompletionRequest;
    const retryMessage = retry.messages.at(-1) as (typeof retry.messages)[number];
    expect((retryMessage.content[0] as { text: string }).text).toContain('verdict must be ok');

    const hopeless = new ScriptedProvider([
      { content: [{ type: 'text', text: 'nope' }] },
      { content: [{ type: 'text', text: 'still nope' }] },
      { content: [{ type: 'text', text: '{"verdict": 1}' }] },
    ]);
    const failed = await runStructured({ provider: hopeless, role: 'r', system: 's', prompt: 'p', schema: Verdict });
    expect(failed.status).toBe('FAILED');
    expect(failed.steps).toHaveLength(3);
  });
});

describe('provider registry', () => {
  const models = {
    cloud: { provider: 'anthropic' as const, model: 'claude-opus-5-5', tool_mode: 'auto' as const },
    local: {
      provider: 'openai-compatible' as const,
      model: 'gemma3:12b',
      base_url: 'http://llm/v1',
      tool_mode: 'auto' as const,
      rate_limit: { concurrency: 3 },
    },
    fast: { provider: 'scripted' as const, model: 'scripted', tool_mode: 'auto' as const },
  };
  it('routes roles with fallbacks and resolves tool mode from the catalog or config', () => {
    const registry = buildRegistry({
      models,
      routing: { deep: 'cloud', map: 'local', fast: 'fast' },
      env: {},
      scripted: () => new ScriptedProvider([]),
      detected: { local: { contextWindow: 65_536, source: 'vllm-models' } },
    });
    expect(registry.aliasOf('deep')).toBe('cloud');
    expect(registry.aliasOf('judge')).toBe('fast');
    expect(registry.aliasOf('reduce')).toBe('cloud');
    expect(registry.aliasOf('summarize')).toBe('fast');
    expect(registry.routed('judge')).toBe(false);
    const local = registry.resolved('local');
    expect(local).toMatchObject({ toolMode: 'prompted', profile: { contextWindow: 65_536 } });
    expect(local?.limiter.limit).toEqual({ concurrency: 3 });
    const provider = registry.for('map')();
    expect(provider.capabilities()).toMatchObject({ toolMode: 'prompted', maxContext: 65_536 });
    expect(registry.for('map')()).toBe(provider);
    const forced = buildRegistry({
      models: { local: { ...models.local, tool_mode: 'native', context_window: 8_192 } },
      env: {},
    });
    expect(forced.resolved('local')).toMatchObject({ toolMode: 'native', profile: { contextWindow: 8_192 } });
    expect(forced.aliasOf('deep')).toBe('local');
  });
});

describe('rate limiter', () => {
  it('enforces rpm, tpm, concurrency and penalties with a fake clock', async () => {
    let t = 0;
    const slept: number[] = [];
    const limiter = new RateLimiter(
      { rpm: 2, tpm: 1_000, concurrency: 1 },
      () => t,
      async (ms) => {
        slept.push(ms);
        t += ms;
      },
    );
    (await limiter.acquire(100))();
    (await limiter.acquire(100))();
    (await limiter.acquire(100))();
    expect(slept.reduce((a, b) => a + b, 0)).toBeGreaterThanOrEqual(60_000);
    (await limiter.acquire(950))();
    expect(t).toBeGreaterThanOrEqual(120_000);
    limiter.penalize(5_000);
    const before = t;
    (await limiter.acquire(1))();
    expect(t - before).toBeGreaterThanOrEqual(5_000);

    let active = 0;
    let peak = 0;
    const gated = new RateLimiter({ concurrency: 1 });
    const inner = new ScriptedProvider(
      Array.from({ length: 3 }, () => () => {
        active++;
        peak = Math.max(peak, active);
        active--;
        return { content: [{ type: 'text' as const, text: 'ok' }] };
      }),
    );
    const limited = withRateLimit(inner, gated);
    await Promise.all([limited.complete(base()), limited.complete(base()), limited.complete(base())]);
    expect(peak).toBe(1);
  });
});
