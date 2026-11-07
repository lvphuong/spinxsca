import { renderDigest } from '@spinxsca/core';
import type { RepoDigest } from '@spinxsca/schemas';
import { z } from 'zod';
import { type AgentTool, defineTool } from '../runtime/tools';

/** `repo_map` (ADR-056): drill into the repository digest instead of listing files. */
export function createRepoMapTool(digest: RepoDigest): AgentTool<never> {
  return defineTool({
    name: 'repo_map',
    description:
      'Show the repository digest for a directory: files, lines, endpoints, controls, data access and external imports per subdirectory. Cheaper than list_files for orientation.',
    input: z.strictObject({
      path: z.string().optional().describe('Directory to expand (repository root when omitted)'),
      depth: z.number().int().min(1).max(3).optional(),
    }),
    risk: 'READ',
    idempotent: true,
    outputLimit: 6_000,
    run: async ({ path, depth }) =>
      renderDigest(digest, { ...(path !== undefined ? { path } : {}), depth: depth ?? 2, maxChars: 6_000 }),
  }) as unknown as AgentTool<never>;
}
