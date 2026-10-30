import { resolve } from 'node:path';
import type { ExplainSubject, FindingExplainer, InvestigationSubject, SourceTree } from '@spinxsca/core';
import { describe, expect, it } from 'vitest';
import {
  AgentInvestigator,
  compileDataPolicy,
  DataPolicyError,
  fromChatResponse,
  loadPromptBundle,
  OpenAICompatibleProvider,
  toChatMessages,
  withDataPolicy,
} from '../src/index';

const PROMPTS = resolve(__dirname, '../../../prompts');
const request = {
  system: 'sys',
  tools: [{ name: 'read_file', description: 'r', inputSchema: { type: 'object' } }],
  maxTokens: 100,
  metadata: { role: 'explain' },
  messages: [
    { role: 'user' as const, content: [{ type: 'text' as const, text: 'go' }] },
    {
      role: 'assistant' as const,
      content: [
        { type: 'text' as const, text: 'reading' },
        { type: 'tool_use' as const, id: 'c1', name: 'read_file', input: { path: 'a.js' } },
      ],
    },
    {
      role: 'user' as const,
      content: [
        { type: 'tool_result' as const, toolUseId: 'c1', content: 'line', isError: true },
        { type: 'text' as const, text: 'continue' },
      ],
    },
  ],
};

describe('OpenAI-compatible provider', () => {
  it('maps tool use and tool results to chat messages in the required order', () => {
    expect(toChatMessages(request)).toEqual([
      { role: 'system', content: 'sys' },
      { role: 'user', content: 'go' },
      {
        role: 'assistant',
        content: 'reading',
        tool_calls: [{ id: 'c1', type: 'function', function: { name: 'read_file', arguments: '{"path":"a.js"}' } }],
      },
      { role: 'tool', tool_call_id: 'c1', content: 'ERROR: line' },
      { role: 'user', content: 'continue' },
    ]);
  });

  it('maps responses, usage and malformed tool arguments', () => {
    const result = fromChatResponse(
      {
        model: 'qwen3-coder',
        choices: [
          {
            finish_reason: 'tool_calls',
            message: { content: null, tool_calls: [{ id: 't', function: { name: 'submit', arguments: '{"a":1}' } }] },
          },
        ],
        usage: { prompt_tokens: 100, completion_tokens: 20, prompt_tokens_details: { cached_tokens: 60 } },
      },
      'requested',
    );
    expect(result).toMatchObject({
      stopReason: 'tool_use',
      model: 'qwen3-coder',
      content: [{ type: 'tool_use', id: 't', name: 'submit', input: { a: 1 } }],
    });
    expect(result.usage).toEqual({ inputTokens: 40, outputTokens: 20, cacheReadTokens: 60, cacheWriteTokens: 0 });
    expect(
      fromChatResponse({ choices: [{ finish_reason: 'length', message: { content: 'x' } }] }, 'm').stopReason,
    ).toBe('max_tokens');
    expect(() =>
      fromChatResponse(
        { choices: [{ message: { tool_calls: [{ id: 't', function: { name: 'f', arguments: '{bad' } }] } }] },
        'm',
      ),
    ).toThrow('invalid JSON');
  });

  it('retries rate limits and sends the API key only when configured', async () => {
    const seen: Array<{ status: number; auth: string | null }> = [];
    let calls = 0;
    const fakeFetch = (async (_url: string, init?: RequestInit) => {
      calls++;
      const auth = new Headers(init?.headers).get('authorization');
      const status = calls === 1 ? 429 : 200;
      seen.push({ status, auth });
      return status === 429
        ? new Response('slow down', { status })
        : new Response(JSON.stringify({ choices: [{ finish_reason: 'stop', message: { content: 'ok' } }] }));
    }) as unknown as typeof fetch;
    const provider = new OpenAICompatibleProvider({
      baseUrl: 'http://llm.local/v1/',
      model: 'm',
      apiKey: 'k',
      fetch: fakeFetch,
      maxRetries: 2,
    });
    const result = await provider.complete({
      ...request,
      messages: [request.messages[0] as (typeof request.messages)[0]],
    });
    expect(result.content).toEqual([{ type: 'text', text: 'ok' }]);
    expect(seen).toEqual([
      { status: 429, auth: 'Bearer k' },
      { status: 200, auth: 'Bearer k' },
    ]);
  });

  it('drives a full agent run (planner + auditor) through chat completions', async () => {
    const bodies: Array<{ messages: Array<{ role: string }>; tools: Array<{ function: { name: string } }> }> = [];
    const fakeFetch = (async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      bodies.push(body);
      const names = body.tools.map((t: { function: { name: string } }) => t.function.name);
      const call = names.includes('submit_threat_model')
        ? {
            name: 'submit_threat_model',
            arguments: JSON.stringify({ summary: 's', trustBoundaries: [], packets: [], notes: [] }),
          }
        : {
            name: 'submit_investigation',
            arguments: JSON.stringify({ findings: [], resolvedQuestions: [], reviewedFiles: [], deferred: [] }),
          };
      return new Response(
        JSON.stringify({
          model: 'local-model',
          choices: [
            {
              finish_reason: 'tool_calls',
              message: { content: null, tool_calls: [{ id: `c${bodies.length}`, function: call }] },
            },
          ],
          usage: { prompt_tokens: 10, completion_tokens: 5 },
        }),
      );
    }) as unknown as typeof fetch;
    const investigator = new AgentInvestigator({
      provider: () =>
        new OpenAICompatibleProvider({ baseUrl: 'http://llm/v1', model: 'local-model', fetch: fakeFetch }),
      prompts: loadPromptBundle(PROMPTS),
    });
    const source: SourceTree = {
      root: '/r',
      listFiles: async () => [],
      readText: async () => 'x',
      gitInfo: async () => undefined,
    };
    const outcome = await investigator.investigate(
      {
        scan: { scanId: 's' } as InvestigationSubject['scan'],
        snapshotPaths: ['a.js'],
        scannerCandidates: [],
        redactions: [],
      },
      source,
      { maxCostUsd: 1 },
    );
    expect(outcome.runs.map((r) => [r.role, r.status, r.provider, r.model])).toEqual([
      ['planner', 'COMPLETED', 'openai-compatible', 'local-model'],
      ['auditor', 'COMPLETED', 'openai-compatible', 'local-model'],
    ]);
    expect(bodies[0]?.messages[0]?.role).toBe('system');
  });
});

describe('AI data policy', () => {
  const allows = compileDataPolicy({ excludePaths: ['secrets', 'config/*.env', '**/*.pem'] });
  it('matches directories, segment wildcards and any-depth patterns', () => {
    expect(['secrets/a.txt', 'config/prod.env', 'deep/x/key.pem'].map(allows)).toEqual([false, false, false]);
    expect(['secretsx/a.txt', 'config/sub/prod.env', 'src/app.js'].map(allows)).toEqual([true, true, true]);
  });

  it('withholds excluded files from roles and refuses findings located in them', async () => {
    let seen: { subject?: ExplainSubject; text?: string | undefined } = {};
    const inner: FindingExplainer = {
      info: { provider: 'x', model: 'x', promptBundleDigest: 'sha256:x', policyVersion: 'p' },
      explain: async (subject, source) => {
        seen = { subject, text: await source.readText('secrets/key.txt') };
        return { run: {} as never };
      },
    };
    const guarded = withDataPolicy(inner, { excludePaths: ['secrets'] });
    const source: SourceTree = {
      root: '/r',
      listFiles: async () => [],
      readText: async () => 'TOP SECRET',
      gitInfo: async () => undefined,
    };
    const subject = (path: string) =>
      ({
        occurrence: { locations: [{ path, startLine: 1, endLine: 1, role: 'primary' }] },
        snapshotPaths: ['src/a.js', 'secrets/key.txt'],
        evidence: [{ locations: [{ path: 'secrets/key.txt', startLine: 1, endLine: 1 }], excerpt: 'TOP SECRET' }],
        related: [{ findingId: 'SPX-2', title: 't', category: 'c', location: 'secrets/key.txt:1' }],
      }) as unknown as ExplainSubject;
    await expect(guarded.explain(subject('secrets/key.txt'), source)).rejects.toBeInstanceOf(DataPolicyError);
    await guarded.explain(subject('src/a.js'), source);
    expect(seen.text).toBeUndefined();
    expect(seen.subject?.snapshotPaths).toEqual(['src/a.js']);
    expect(seen.subject?.evidence[0]?.excerpt).toBe('[withheld by data policy]');
    expect(seen.subject?.related).toEqual([]);
  });
});
