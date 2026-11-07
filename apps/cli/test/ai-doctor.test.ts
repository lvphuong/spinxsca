import { describe, expect, it } from 'vitest';
import { runDoctor } from '../src/commands/ai-doctor';

/** Fake vLLM-style server: lists models, answers tool calls natively or as prose, and JSON. */
function fakeServer(mode: 'native' | 'prose' | 'none') {
  const bodies: Array<Record<string, unknown>> = [];
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
  const fetchMock = (async (url: string, init?: RequestInit) => {
    const u = String(url);
    if (u.endsWith('/v1/models')) return json({ data: [{ id: 'qwen2.5-coder:14b', max_model_len: 24_000 }] });
    if (u.endsWith('/api/show')) return json({ error: 'not ollama' }, 404);
    if (u.endsWith('/api/v0/models')) return json({}, 404);
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    bodies.push(body);
    const tools = body.tools as Array<{ function: { name: string } }> | undefined;
    const system = (body.messages as Array<{ role: string; content: string }>)[0]?.content ?? '';
    const prompted = system.includes('### echo_probe');
    const usage = { prompt_tokens: 1200, completion_tokens: 40 };
    if (tools?.length && mode === 'native')
      return json({
        choices: [
          {
            finish_reason: 'tool_calls',
            message: {
              content: null,
              tool_calls: [{ id: 'c1', function: { name: 'echo_probe', arguments: '{"value":"ok"}' } }],
            },
          },
        ],
        usage,
      });
    if (prompted && mode !== 'none')
      return json({
        choices: [
          {
            finish_reason: 'stop',
            message: { content: 'Calling.\n<tool_call>{"name":"echo_probe","arguments":{"value":"ok"}}</tool_call>' },
          },
        ],
        usage,
      });
    if (body.response_format)
      return json({
        choices: [
          { finish_reason: 'stop', message: { content: '```json\n{"verdict":"ok","reason":"all good",}\n```' } },
        ],
        usage,
      });
    return json({ choices: [{ finish_reason: 'stop', message: { content: 'Caching stores responses…' } }], usage });
  }) as unknown as typeof fetch;
  return { fetchMock, bodies };
}

const target = {
  provider: 'openai-compatible' as const,
  model: 'qwen2.5-coder:14b',
  base_url: 'http://llm.local:8000/v1',
  tool_mode: 'auto' as const,
};

describe('spinxsca ai doctor', () => {
  it('passes every check on a capable endpoint and recommends native tools', async () => {
    let t = 0;
    const { fetchMock } = fakeServer('native');
    const report = await runDoctor(target, { fetch: fetchMock, env: {}, now: () => (t += 250) });
    expect(report.checks.map((c) => [c.name, c.ok])).toEqual([
      ['endpoint', true],
      ['context', true],
      ['native tool call', true],
      ['prompted tool call', true],
      ['json submit', true],
      ['throughput', true],
    ]);
    expect(report.contextWindow).toBe(24_000);
    expect(report.toolMode).toBe('native');
    expect(report.ok).toBe(true);
    expect(report.recommendation.yaml).toContain('tool_mode: native');
    expect(report.recommendation.yaml).toContain('context_window: 24000');
    expect(report.recommendation.yaml).toContain('map: local');
    expect(report.tokensPerSecond?.generate).toBeGreaterThan(0);
  });

  it('falls back to prompted tools when the model answers in prose', async () => {
    const { fetchMock } = fakeServer('prose');
    const report = await runDoctor(target, { fetch: fetchMock, env: {} });
    expect(report.checks.find((c) => c.name === 'native tool call')?.ok).toBe(false);
    expect(report.checks.find((c) => c.name === 'prompted tool call')?.ok).toBe(true);
    expect(report.toolMode).toBe('prompted');
    expect(report.recommendation.yaml).toContain('tool_mode: prompted');
  });

  it('reports a model without tool calling as JSON-only with a warning', async () => {
    const { fetchMock } = fakeServer('none');
    const report = await runDoctor(target, { fetch: fetchMock, env: {} });
    expect(report.toolMode).toBe('none');
    expect(report.ok).toBe(false);
    expect(report.recommendation.warnings.join(' ')).toContain('no tool calling');
  });
});
