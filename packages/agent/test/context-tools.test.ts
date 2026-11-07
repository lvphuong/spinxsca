import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { SourceTree } from '@spinxsca/core';
import { afterAll, describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  boundOutput,
  collapseView,
  contextBudgetFor,
  createCodeTools,
  createReadResultTool,
  createSearcher,
  defineTool,
  LruLineCache,
  llmSummarizer,
  MemoryResultStore,
  type Message,
  PlainToolExecutor,
  promptBudgetFor,
  ripgrepPath,
  ScriptedProvider,
  summaryInput,
  validSummary,
} from '../src/index';

const dir = mkdtempSync(join(tmpdir(), 'spinxsca-ctx-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('out-of-band tool results (ADR-056)', () => {
  it('stores large results and pages them through read_result', async () => {
    const store = new MemoryResultStore();
    const big = 'x'.repeat(100_000);
    const shown = await boundOutput(big, { inlineChars: 4_000, store, tool: 'read_file' });
    expect(shown.length).toBeLessThan(4_300);
    const handle = /handle="(res_[0-9a-f]{16})"/.exec(shown)?.[1] as string;
    expect(handle).toBeDefined();
    const tool = createReadResultTool(store, 4_000);
    const page = await tool.run({ handle, offset: 4_000, limit: 10 } as never, {});
    expect(page).toContain('[chars 4000-4010 of 100000] Continue with offset=4010.');
    await expect(tool.run({ handle: 'res_0000000000000000' } as never, {})).rejects.toThrow('not a stored result');
    expect(await boundOutput('short', { inlineChars: 100, store, tool: 't' })).toBe('short');
    expect(await boundOutput(big, { inlineChars: 10, tool: 't' })).toContain(
      '[output truncated: 99990 more characters]',
    );
  });

  it('PlainToolExecutor caps every result (regression: it used to return unbounded output)', async () => {
    const noisy = defineTool({
      name: 'noisy',
      description: 'n',
      input: z.strictObject({}),
      run: async () => 'y'.repeat(50_000),
    });
    const plain = new PlainToolExecutor([noisy]);
    const out = await plain.execute({ type: 'tool_use', id: 'a', name: 'noisy', input: {} }, {});
    expect(out.kind === 'result' && out.content.length).toBeLessThan(20_200);
    const stored = new PlainToolExecutor([noisy], { inlineChars: 1_000, store: new MemoryResultStore() });
    const out2 = await stored.execute({ type: 'tool_use', id: 'a', name: 'noisy', input: {} }, {});
    expect(out2.kind === 'result' && out2.content).toContain('read_result(handle=');
  });
});

describe('search backends and the shared line cache', () => {
  const files: Record<string, string> = {
    'src/a.ts': 'const token = 1;\nfindOne(id)\n',
    'src/b.ts': 'findOne(other)\nnothing\n',
    'secret/c.ts': 'findOne(hidden)\n',
  };
  it('scans with pagination, honours allowed paths and prefixes, and evicts from the LRU', async () => {
    const cache = new LruLineCache(2, 1_000_000);
    const readLines = async (p: string) => {
      const text = files[p];
      if (text === undefined) return undefined;
      const lines = text.split('\n');
      cache.set(p, lines);
      return lines;
    };
    const searcher = createSearcher({ root: '/nonexistent', readLines, paths: Object.keys(files) });
    const allowed = new Set(['src/a.ts', 'src/b.ts']);
    const first = await searcher.search({ query: 'findOne', limit: 1, allowed });
    expect(first).toMatchObject({ backend: 'scan', truncated: true, hits: [{ path: 'src/a.ts', line: 2 }] });
    const second = await searcher.search({ query: 'findOne', limit: 5, offset: 1, allowed });
    expect(second.hits).toEqual([{ path: 'src/b.ts', line: 1, text: 'findOne(other)' }]);
    expect(second.truncated).toBe(false);
    const prefixed = await searcher.search({
      query: 'findone',
      ignoreCase: true,
      limit: 5,
      allowed,
      pathPrefix: 'src/b',
    });
    expect(prefixed.hits.map((h) => h.path)).toEqual(['src/b.ts']);
    expect(cache.size).toBeLessThanOrEqual(2);
  });

  it('search_code pages results and never leaves the snapshot', async () => {
    const source: SourceTree = {
      root: '/virtual',
      listFiles: async () => [],
      readText: async (p) => files[p],
      gitInfo: async () => undefined,
    };
    const tools = createCodeTools({ source, paths: ['src/a.ts', 'src/b.ts'], redactions: [] });
    const search = tools.find((t) => t.name === 'search_code') as (typeof tools)[number];
    const page1 = await search.run({ query: 'findOne', max_results: 1 } as never, {});
    expect(page1).toContain('src/a.ts:2');
    expect(page1).toContain('offset=1');
    const page2 = await search.run({ query: 'findOne', max_results: 1, offset: 1 } as never, {});
    expect(page2).toContain('src/b.ts:1');
    expect(page2).not.toContain('secret/c.ts');
  });

  it('uses ripgrep when available and the root exists', async () => {
    const rg = await ripgrepPath();
    if (!rg) return;
    const root = join(dir, 'repo');
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, 'src', 'a.ts'), 'needle here\n');
    writeFileSync(join(root, 'src', 'b.ts'), 'needle again\n');
    const searcher = createSearcher({
      root,
      readLines: async () => undefined,
      paths: ['src/a.ts', 'src/b.ts'],
      rgPath: rg,
    });
    const result = await searcher.search({ query: 'needle', limit: 5, allowed: new Set(['src/a.ts']) });
    expect(result.backend).toBe('ripgrep');
    expect(result.hits).toEqual([{ path: 'src/a.ts', line: 1, text: 'needle here' }]);
  });
});

describe('compaction summaries and budgets', () => {
  const messages: Message[] = [
    { role: 'user', content: [{ type: 'text', text: 'TASK' }] },
    { role: 'assistant', content: [{ type: 'tool_use', id: 'u1', name: 'read_file', input: { path: 'a.ts' } }] },
    { role: 'user', content: [{ type: 'tool_result', toolUseId: 'u1', content: 'SECRET_OUTPUT' }] },
    { role: 'assistant', content: [{ type: 'text', text: 'found it' }] },
    { role: 'user', content: [{ type: 'text', text: 'go on' }] },
    { role: 'assistant', content: [{ type: 'tool_use', id: 'u2', name: 'read_file', input: { path: 'b.ts' } }] },
    { role: 'user', content: [{ type: 'tool_result', toolUseId: 'u2', content: 'more' }] },
    { role: 'assistant', content: [{ type: 'text', text: 'done' }] },
  ];

  it('feeds the summariser text and calls only, validates headings, and falls back otherwise', async () => {
    const input = summaryInput(messages);
    expect(input).toContain('call read_file({"path":"a.ts"})');
    expect(input).not.toContain('SECRET_OUTPUT');
    const good = [
      '## Goal',
      'x',
      '## Constraints',
      '## Progress',
      '## Decisions',
      '## Next steps',
      '## Files examined',
      'a.ts',
      '## Open checklist rows',
    ].join('\n');
    expect(validSummary(good)).toBe(true);
    expect(validSummary('## Goal only')).toBe(false);
    const provider = new ScriptedProvider([
      { content: [{ type: 'text', text: good }] },
      { content: [{ type: 'text', text: 'nope' }] },
    ]);
    const summarize = llmSummarizer(() => provider, { system: 'sum', scrub: (t) => t.replace('a.ts', '<p>') });
    expect(await summarize(messages.slice(1, 5))).toBe(good);
    expect(JSON.stringify(provider.requests[0]?.messages)).toContain('<p>');
    await expect(summarize(messages.slice(1, 5))).rejects.toThrow('missing mandatory headings');
  });

  it('collapses the middle keeping pairs intact', () => {
    const view = collapseView(messages, { keepLastTurns: 1 });
    expect(view).toHaveLength(2);
    expect(JSON.stringify(view[0])).toContain('files already examined: a.ts, b.ts');
    expect(view[1]?.role).toBe('assistant');
    expect(collapseView(messages.slice(0, 2))).toHaveLength(2);
  });

  it('scales prompt budgets with the window', () => {
    const small = promptBudgetFor(
      contextBudgetFor({ maxContext: 32_768, maxOutput: 8_192 }, { maxOutputTokens: 32_000 }),
      'recon',
    );
    const large = promptBudgetFor(
      contextBudgetFor({ maxContext: 200_000, maxOutput: 32_000 }, { maxOutputTokens: 32_000 }),
      'recon',
    );
    expect(small.groundTruth).toBeGreaterThan(5_000);
    expect(small.groundTruth).toBeLessThan(15_000);
    expect(large.groundTruth).toBeGreaterThan(70_000);
    expect(large.total).toBe(Math.floor(180_000 * 4 * 0.3));
  });
});
