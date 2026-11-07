import type { SourceTree } from '@spinxsca/core';
import { applyRedactions, type RedactionSpan, redactSecrets } from '@spinxsca/core';
import { z } from 'zod';
import { type AgentTool, defineTool } from '../runtime/tools';
import { createSearcher, LruLineCache, type Searcher } from './search';

const MAX_READ_LINES = 300;
const MAX_SEARCH_RESULTS = 50;
const MAX_LINE_CHARS = 240;
const MAX_FILE_BYTES = 1_000_000;

export interface CodeToolContext {
  source: SourceTree;
  /** Only these paths may be read or searched (the scan snapshot). */
  paths: readonly string[];
  redactions: readonly RedactionSpan[];
  findings?: ReadonlyArray<{ findingId: string; title: string; category: string; location: string }>;
  /** Shared across the roles of one scan so a large repository is split and cached once (ADR-056). */
  cache?: LruLineCache;
  searcher?: Searcher;
}

/**
 * Read-only code tools (docs/architecture/03 section 5). Every read goes through the source tree's
 * confinement, is limited to snapshot paths and is redacted before the model sees it.
 */
export function createCodeTools(ctx: CodeToolContext): AgentTool<never>[] {
  const allowed = new Set(ctx.paths);
  // Bounded: old files are evicted instead of pinning the whole repository per role instance.
  const cache = ctx.cache ?? new LruLineCache();
  const linesOf = async (path: string): Promise<string[] | undefined> => {
    if (!allowed.has(path)) return undefined;
    if (!cache.has(path)) {
      const text = await ctx.source.readText(path);
      cache.set(
        path,
        text === undefined || text.length > MAX_FILE_BYTES || text.includes('\u0000') ? undefined : text.split(/\r?\n/),
      );
    }
    return cache.get(path);
  };
  const searcher = ctx.searcher ?? createSearcher({ root: ctx.source.root, readLines: linesOf, paths: ctx.paths });
  const clean = (path: string, lines: string[], first: number): string[] =>
    applyRedactions(lines, first, path, ctx.redactions).map((l) => redactSecrets(l).text);

  const readFile = defineTool({
    name: 'read_file',
    description: `Read lines of a repository file (at most ${MAX_READ_LINES} lines per call). Lines are numbered.`,
    input: z.strictObject({
      path: z.string().describe('Repository-relative path'),
      start_line: z.number().int().positive().optional(),
      end_line: z.number().int().positive().optional(),
    }),
    run: async ({ path, start_line, end_line }) => {
      const lines = await linesOf(path);
      if (!lines) throw new Error(`${path} is not a readable text file in this snapshot`);
      const start = Math.min(Math.max(1, start_line ?? 1), lines.length);
      const end = Math.min(lines.length, end_line ?? start + MAX_READ_LINES - 1, start + MAX_READ_LINES - 1);
      const body = clean(path, lines.slice(start - 1, end), start)
        .map((l, i) => `${String(start + i).padStart(5)} | ${l}`)
        .join('\n');
      return `<untrusted_repository_content path="${path}" lines="${start}-${end}" total_lines="${lines.length}">\n${body}\n</untrusted_repository_content>`;
    },
  });

  const searchCode = defineTool({
    name: 'search_code',
    description:
      'Find lines containing a literal string (not a regular expression) across the snapshot. Results are paged: pass offset to continue.',
    input: z.strictObject({
      query: z.string().min(2).max(200),
      path_prefix: z.string().optional().describe('Only search paths starting with this prefix'),
      ignore_case: z.boolean().optional(),
      max_results: z.number().int().positive().max(MAX_SEARCH_RESULTS).optional(),
      offset: z.number().int().nonnegative().optional().describe('Skip this many matches (paging)'),
    }),
    run: async ({ query, path_prefix, ignore_case, max_results, offset }) => {
      const limit = max_results ?? 30;
      const result = await searcher.search({
        query,
        ...(path_prefix ? { pathPrefix: path_prefix } : {}),
        ...(ignore_case ? { ignoreCase: true } : {}),
        limit,
        ...(offset ? { offset } : {}),
        allowed,
      });
      const hits = result.hits.map((h) => {
        const [shown] = clean(h.path, [h.text], h.line);
        return `${h.path}:${h.line}: ${(shown ?? '').trim().slice(0, MAX_LINE_CHARS)}`;
      });
      if (hits.length === 0) return offset ? 'No more matches.' : 'No matches.';
      const next = (offset ?? 0) + hits.length;
      return `<untrusted_repository_content>\n${hits.join('\n')}\n</untrusted_repository_content>${result.truncated ? `\n… more matches; call again with offset=${next}` : ''}`;
    },
  });

  const listFiles = defineTool({
    name: 'list_files',
    description: 'List repository files, optionally under a path prefix (at most 300).',
    input: z.strictObject({ path_prefix: z.string().optional() }),
    run: async ({ path_prefix }) => {
      const matches = ctx.paths.filter((p) => !path_prefix || p.startsWith(path_prefix));
      const shown = matches.slice(0, 300);
      return (
        `${shown.join('\n')}${matches.length > shown.length ? `\n... ${matches.length - shown.length} more` : ''}` ||
        'No files.'
      );
    },
  });

  const tools: AgentTool<never>[] = [readFile, searchCode, listFiles] as unknown as AgentTool<never>[];
  if (ctx.findings) {
    const findings = ctx.findings;
    tools.push(
      defineTool({
        name: 'list_findings',
        description: 'List other findings recorded for this scan.',
        input: z.strictObject({}),
        run: async () =>
          findings.length
            ? findings.map((f) => `${f.findingId} ${f.category} ${f.location} ${f.title}`).join('\n')
            : 'No other findings.',
      }) as unknown as AgentTool<never>,
    );
  }
  return tools;
}

/** Checks that cited locations exist in the snapshot (ADR-022: the host validates model output). */
export async function checkCitations(
  ctx: Pick<CodeToolContext, 'source' | 'paths'>,
  citations: ReadonlyArray<{ path: string; startLine: number; endLine: number }>,
): Promise<string[]> {
  const allowed = new Set(ctx.paths);
  const problems: string[] = [];
  for (const [i, c] of citations.entries()) {
    if (!allowed.has(c.path)) {
      problems.push(`citation ${i + 1}: ${c.path} is not a file in this snapshot`);
      continue;
    }
    if (c.endLine < c.startLine) {
      problems.push(`citation ${i + 1}: endLine ${c.endLine} is before startLine ${c.startLine}`);
      continue;
    }
    const lines = (await ctx.source.readText(c.path))?.split(/\r?\n/).length ?? 0;
    if (c.endLine > lines) problems.push(`citation ${i + 1}: ${c.path} has ${lines} lines, not ${c.endLine}`);
  }
  return problems;
}
