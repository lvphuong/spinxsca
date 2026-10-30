import type Anthropic from '@anthropic-ai/sdk';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  AnthropicProvider,
  defineTool,
  fromMessage,
  runAgent,
  ScriptedProvider,
  toolSpec,
  toParam,
} from '../src/index';

const Verdict = z.strictObject({
  classification: z.enum(['CONFIRMED', 'POTENTIAL', 'UNLIKELY']),
  reasoning: z.string().min(1),
});

const readFile = defineTool({
  name: 'code_read',
  description: 'Read a file',
  input: z.strictObject({ path: z.string() }),
  run: async ({ path }) => `contents of ${path}`,
});

const submit = { name: 'submit_verdict', description: 'Submit the verdict', output: Verdict };

describe('runAgent', () => {
  it('runs tools, rejects an invalid submission and accepts a corrected one', async () => {
    const provider = new ScriptedProvider([
      { content: [{ type: 'tool_use', id: 't1', name: 'code_read', input: { path: 'a.js' } }] },
      { content: [{ type: 'tool_use', id: 't2', name: 'submit_verdict', input: { classification: 'MAYBE' } }] },
      {
        content: [
          { type: 'text', text: 'Submitting.' },
          {
            type: 'tool_use',
            id: 't3',
            name: 'submit_verdict',
            input: { classification: 'POTENTIAL', reasoning: 'sink reachable' },
          },
        ],
      },
    ]);
    const result = await runAgent({ role: 'validator', provider, system: 's', prompt: 'p', tools: [readFile], submit });
    expect(result.status).toBe('COMPLETED');
    expect(result.output).toEqual({ classification: 'POTENTIAL', reasoning: 'sink reachable' });
    expect(result.steps).toHaveLength(3);
    expect(result.usage.inputTokens).toBe(300);

    const second = provider.requests[1]?.messages.at(-1);
    expect(second?.content[0]).toEqual({ type: 'tool_result', toolUseId: 't1', content: 'contents of a.js' });
    const third = provider.requests[2]?.messages.at(-1)?.content[0];
    expect(third).toMatchObject({ type: 'tool_result', toolUseId: 't2', isError: true });
    expect((third as { content: string }).content).toContain('classification');
    expect(provider.requests[0]?.tools.map((t) => t.name)).toEqual(['code_read', 'submit_verdict']);
  });

  it('nudges a model that answers in text and fails after repeated non-submission', async () => {
    const provider = new ScriptedProvider([
      { content: [{ type: 'text', text: 'I think it is fine.' }] },
      { content: [{ type: 'text', text: 'Still fine.' }] },
      { content: [{ type: 'text', text: 'Done.' }] },
    ]);
    const result = await runAgent({ role: 'r', provider, system: 's', prompt: 'p', tools: [], submit });
    expect(result.status).toBe('FAILED');
    expect(provider.requests[1]?.messages.at(-1)?.content[0]).toMatchObject({ type: 'text' });
  });

  it('stops on refusal without running tools', async () => {
    const provider = new ScriptedProvider([{ content: [], stopReason: 'refusal', refusal: { category: 'cyber' } }]);
    const result = await runAgent({ role: 'r', provider, system: 's', prompt: 'p', tools: [readFile], submit });
    expect(result.status).toBe('REFUSED');
    expect(result.refusal?.category).toBe('cyber');
  });

  it('enforces the step budget', async () => {
    const loop = () => ({
      content: [{ type: 'tool_use' as const, id: `t${Math.random()}`, name: 'code_read', input: { path: 'x' } }],
    });
    const provider = new ScriptedProvider([loop, loop, loop]);
    const result = await runAgent({
      role: 'r',
      provider,
      system: 's',
      prompt: 'p',
      tools: [readFile],
      submit,
      budget: { maxSteps: 2 },
    });
    expect(result.status).toBe('BUDGET_EXHAUSTED');
    expect(result.steps).toHaveLength(2);
  });

  it('does not run tools from a turn truncated at max_tokens', async () => {
    let ran = false;
    const tool = defineTool({
      name: 'act',
      description: 'd',
      input: z.strictObject({}),
      run: async () => {
        ran = true;
        return 'ok';
      },
    });
    const provider = new ScriptedProvider([
      { content: [{ type: 'tool_use', id: 't', name: 'act', input: {} }], stopReason: 'max_tokens' },
    ]);
    const result = await runAgent({ role: 'r', provider, system: 's', prompt: 'p', tools: [tool], submit });
    expect(result.status).toBe('FAILED');
    expect(ran).toBe(false);
  });
});

describe('toolSpec', () => {
  it('produces an object JSON schema without $schema', () => {
    const spec = toolSpec('x', 'd', z.strictObject({ path: z.string(), depth: z.number().int().optional() }));
    expect(spec.inputSchema).toMatchObject({ type: 'object', required: ['path'], additionalProperties: false });
    expect(spec.inputSchema.$schema).toBeUndefined();
  });
});

describe('Anthropic mapping', () => {
  const message = (content: unknown[], extra: Record<string, unknown> = {}) =>
    ({
      id: 'msg',
      type: 'message',
      role: 'assistant',
      model: 'claude-opus-5-5',
      content,
      stop_reason: 'tool_use',
      stop_details: null,
      usage: { input_tokens: 10, output_tokens: 5, cache_read_input_tokens: 7, cache_creation_input_tokens: null },
      ...extra,
    }) as unknown as Anthropic.Beta.BetaMessage;

  it('keeps thinking blocks opaque so they replay unchanged', () => {
    const thinking = { type: 'thinking', thinking: '', signature: 'sig' };
    const result = fromMessage(
      message([thinking, { type: 'tool_use', id: 't', name: 'code_read', input: { path: 'a' } }]),
    );
    expect(result.content[0]).toEqual({ type: 'opaque', provider: 'anthropic', block: thinking });
    expect(result.usage).toEqual({ inputTokens: 10, outputTokens: 5, cacheReadTokens: 7, cacheWriteTokens: 0 });
    expect(toParam({ role: 'assistant', content: result.content }).content).toEqual([
      thinking,
      { type: 'tool_use', id: 't', name: 'code_read', input: { path: 'a' } },
    ]);
  });

  it('drops pre-fallback internal blocks and records the switch', () => {
    const result = fromMessage(
      message(
        [
          { type: 'thinking', thinking: '', signature: 'a' },
          { type: 'text', text: 'partial ' },
          { type: 'tool_use', id: 'old', name: 'code_read', input: {} },
          { type: 'fallback', from: { model: 'claude-opus-5-5' }, to: { model: 'claude-opus-4-8' } },
          { type: 'tool_use', id: 'new', name: 'code_read', input: { path: 'b' } },
        ],
        { model: 'claude-opus-4-8' },
      ),
    );
    expect(result.fallbacks).toEqual([{ from: 'claude-opus-5-5', to: 'claude-opus-4-8' }]);
    expect(result.content.map((b) => (b.type === 'tool_use' ? b.id : b.type))).toEqual(['text', 'new']);
    expect(result.model).toBe('claude-opus-4-8');
  });

  it('maps refusals with their category', () => {
    const result = fromMessage(
      message([], { stop_reason: 'refusal', stop_details: { type: 'refusal', category: 'cyber', explanation: 'x' } }),
    );
    expect(result.stopReason).toBe('refusal');
    expect(result.refusal).toEqual({ category: 'cyber', explanation: 'x' });
  });
});

// Live smoke test against the Claude API. Opt-in only, so CI and local runs never spend tokens by accident.
describe.runIf(process.env.SPINXSCA_LIVE_TESTS === '1')('AnthropicProvider (live)', () => {
  it('completes a tool-use round trip', async () => {
    const provider = new AnthropicProvider({ effort: 'low' });
    const result = await runAgent({
      role: 'smoke',
      provider,
      system: 'You are a test harness. Follow the instructions exactly.',
      prompt: 'Read the file "a.js" with code_read, then submit classification UNLIKELY with a one-sentence reasoning.',
      tools: [readFile],
      submit,
      budget: { maxSteps: 5, maxOutputTokens: 4_000 },
    });
    expect(result.status).toBe('COMPLETED');
    expect(result.output?.classification).toBe('UNLIKELY');
  }, 180_000);
});
