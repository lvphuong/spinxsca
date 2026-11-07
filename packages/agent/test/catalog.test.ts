import { describe, expect, it } from 'vitest';
import {
  CONSERVATIVE_PROFILE,
  clampMaxTokens,
  compactionFor,
  contextBudgetFor,
  costOf,
  detectModelProfile,
  lookupProfile,
  originOf,
  resolveProfile,
} from '../src/index';

describe('model catalog', () => {
  it('matches local model ids with tags and vendor paths', () => {
    expect(lookupProfile('qwen2.5-coder:14b')).toMatchObject({
      contextWindow: 32_768,
      toolMode: 'native',
      tier: 'local',
    });
    expect(lookupProfile('Qwen/Qwen2.5-Coder-14B-Instruct')?.contextWindow).toBe(32_768);
    expect(lookupProfile('deepseek-r1:14b')).toMatchObject({ toolMode: 'prompted', reasoningTags: true });
    expect(lookupProfile('gemma3:12b')?.toolMode).toBe('prompted');
    expect(lookupProfile('claude-opus-5-5')).toMatchObject({
      contextWindow: 200_000,
      promptCaching: true,
      tier: 'deep',
    });
  });

  it('falls back to conservative defaults for unknown models and keeps overrides', () => {
    expect(lookupProfile('mystery-7b')).toBeUndefined();
    const profile = resolveProfile('mystery-7b', { contextWindow: 65_536, toolMode: undefined });
    expect(profile).toMatchObject({ ...CONSERVATIVE_PROFILE, id: 'mystery-7b', contextWindow: 65_536 });
  });

  it('prices only models with a catalog price', () => {
    const usage = { inputTokens: 1_000_000, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };
    expect(costOf(usage, 'claude-opus-5-5')).toBe(4);
    expect(costOf(usage, 'scripted')).toBe(0);
    expect(costOf(usage, 'claude-unknown-9')).toBeUndefined();
    expect(costOf(usage, 'qwen2.5-coder:14b')).toBeUndefined();
  });
});

describe('context budget', () => {
  it('derives thresholds from the window', () => {
    const claude = contextBudgetFor({ maxContext: 200_000, maxOutput: 32_000 }, { maxOutputTokens: 32_000 });
    expect(claude).toMatchObject({
      reserveOutput: 20_000,
      effective: 180_000,
      buffer: 13_000,
      compactThreshold: 167_000,
    });
    const qwen = contextBudgetFor({ maxContext: 32_768, maxOutput: 8_192 }, { maxOutputTokens: 32_000 });
    expect(qwen).toMatchObject({ maxOutput: 8_192, reserveOutput: 8_192, effective: 24_576, buffer: 2_000 });
    expect(qwen.compactThreshold).toBe(22_576);
    expect(qwen.inlineResultChars).toBeGreaterThanOrEqual(4_000);
    expect(compactionFor(qwen)).toMatchObject({ thresholdTokens: 22_576, keepTurns: 3 });
    expect(compactionFor(claude).keepTurns).toBe(6);
  });

  it('clamps max_tokens to what fits after the input', () => {
    const b = contextBudgetFor({ maxContext: 16_000, maxOutput: 2_000 }, { maxOutputTokens: 32_000 });
    expect(clampMaxTokens(b, 1_000)).toBe(2_000);
    expect(clampMaxTokens(b, 15_500)).toBe(1_024);
    expect(clampMaxTokens(b, 14_000)).toBe(1_744);
  });
});

describe('endpoint detection', () => {
  const json = (body: unknown, ok = true) =>
    ({ ok, status: ok ? 200 : 404, json: async () => body, text: async () => JSON.stringify(body) }) as Response;

  it('reads Ollama context length and num_ctx', async () => {
    const calls: string[] = [];
    const fetchMock = (async (url: string | URL | Request) => {
      calls.push(String(url));
      if (String(url).endsWith('/api/show'))
        return json({ model_info: { 'qwen2.context_length': 32768 }, parameters: 'stop "<|im_end|>"\nnum_ctx 16384' });
      return json({}, false);
    }) as unknown as typeof fetch;
    const detected = await detectModelProfile({
      baseUrl: 'http://localhost:11434/v1',
      model: 'qwen2.5-coder',
      fetch: fetchMock,
    });
    expect(detected).toMatchObject({ contextWindow: 32_768, numCtx: 16_384, source: 'ollama-show' });
    expect(calls[0]).toBe('http://localhost:11434/api/show');
    expect(originOf('http://h:8000/v1/')).toBe('http://h:8000');
  });

  it('reads vLLM max_model_len and never throws', async () => {
    const vllm = (async (url: string | URL | Request) => {
      if (String(url).endsWith('/v1/models')) return json({ data: [{ id: 'm', max_model_len: 65536 }] });
      return json({}, false);
    }) as unknown as typeof fetch;
    expect(await detectModelProfile({ baseUrl: 'http://h:8000/v1', model: 'm', fetch: vllm })).toMatchObject({
      contextWindow: 65_536,
      source: 'vllm-models',
    });
    const down = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    expect(await detectModelProfile({ baseUrl: 'http://h:1', model: 'm', fetch: down })).toEqual({ source: 'none' });
  });
});
