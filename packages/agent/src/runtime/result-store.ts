import type { ArtifactStore } from '@spinxsca/core';
import { sha256Hex } from '@spinxsca/core';
import type { Digest } from '@spinxsca/schemas';
import { z } from 'zod';
import { type AgentTool, defineTool } from './tools';

/**
 * Out-of-band tool results (ADR-056). A tool result larger than the inline budget is stored under a
 * content-addressed handle; the model sees the first page plus the handle and reads further pages
 * with `read_result` only when it needs them, so one large file or search never fills the window.
 */
export interface ResultStore {
  put(text: string, meta: { tool: string; toolUseId?: string }): Promise<{ handle: string; bytes: number }>;
  get(handle: string): Promise<string | undefined>;
}

export const READ_RESULT_TOOL = 'read_result';
const HANDLE = /^res_[0-9a-f]{16}$/;

export const handleOf = (text: string): string => `res_${sha256Hex(text).slice(0, 16)}`;

/** Session-local store: results live as long as the process; a resumed run re-reads the file instead. */
export class MemoryResultStore implements ResultStore {
  private readonly entries = new Map<string, string>();

  async put(text: string): Promise<{ handle: string; bytes: number }> {
    const handle = handleOf(text);
    this.entries.set(handle, text);
    return { handle, bytes: text.length };
  }

  async get(handle: string): Promise<string | undefined> {
    return this.entries.get(handle);
  }
}

/** Durable store on the scan's artifact store: handles survive a resume. */
export function artifactResultStore(artifacts: ArtifactStore): ResultStore {
  const digests = new Map<string, Digest>();
  return {
    async put(text) {
      const ref = await artifacts.put(text, 'text/plain');
      const handle = handleOf(text);
      digests.set(handle, ref.digest);
      return { handle, bytes: text.length };
    },
    async get(handle) {
      const digest = digests.get(handle);
      return digest ? artifacts.getText(digest) : undefined;
    },
  };
}

/**
 * Returns the text when it fits, otherwise stores it and returns the first page with the handle.
 * Without a store the text is truncated with a note (the previous behaviour).
 */
export async function boundOutput(
  raw: string,
  options: { inlineChars: number; store?: ResultStore; tool: string; toolUseId?: string },
): Promise<string> {
  if (raw.length <= options.inlineChars) return raw;
  if (!options.store)
    return `${raw.slice(0, options.inlineChars)}\n[output truncated: ${raw.length - options.inlineChars} more characters]`;
  const { handle } = await options.store.put(raw, {
    tool: options.tool,
    ...(options.toolUseId ? { toolUseId: options.toolUseId } : {}),
  });
  return `${raw.slice(0, options.inlineChars)}\n[result truncated: ${raw.length} chars total; showing 1-${options.inlineChars}. Read more with ${READ_RESULT_TOOL}(handle="${handle}", offset=${options.inlineChars}) only if you need it]`;
}

/** `read_result`: one page of a stored result. */
export function createReadResultTool(store: ResultStore, pageChars: number): AgentTool<never> {
  return defineTool({
    name: READ_RESULT_TOOL,
    description: `Read a page of a large earlier tool result by its handle (at most ${pageChars} characters per call).`,
    input: z.strictObject({
      handle: z.string().regex(HANDLE),
      offset: z.number().int().nonnegative().optional(),
      limit: z.number().int().positive().max(pageChars).optional(),
    }),
    risk: 'READ',
    idempotent: true,
    outputLimit: pageChars + 200,
    run: async ({ handle, offset, limit }) => {
      const text = await store.get(handle);
      if (text === undefined)
        throw new Error(`${handle} is not a stored result of this session; call the original tool again`);
      const start = Math.min(offset ?? 0, text.length);
      const end = Math.min(text.length, start + (limit ?? pageChars));
      const more = end < text.length ? ` Continue with offset=${end}.` : ' End of result.';
      return `[chars ${start}-${end} of ${text.length}]${more}\n${text.slice(start, end)}`;
    },
  }) as unknown as AgentTool<never>;
}
