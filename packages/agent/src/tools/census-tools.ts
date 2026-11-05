import { type DataAccessScope, type ResourceMatrix, renderGroup } from '@spinxsca/core';
import { z } from 'zod';
import { type AgentTool, defineTool } from '../runtime/tools';

const MAX_ROWS = 200;
const MAX_SITES = 100;

/**
 * Census tools (ADR-049): the deterministic resource × operation matrix and data-access sites as
 * READ tools. Both return evidence to verify, never a verdict; the descriptions say so because a
 * model that treats a `[!]` row as a finding without reading the handler produces false positives.
 */
export function createCensusTools(matrix: ResourceMatrix): AgentTool<never>[] {
  const tools = [
    defineTool({
      name: 'resource_matrix',
      description:
        'Resource × operation worksheet built deterministically from the code index: endpoints grouped by controller or route noun, with name-classified controls, whether the handler reads an object identifier, and the data-access calls it reaches. A [!] row lacks an authorization control that a sibling has. Evidence to verify by reading the handler and any service-layer check; not a verdict.',
      input: z.strictObject({
        group: z.string().optional().describe('Only this resource group (controller class or route noun)'),
        path_prefix: z.string().optional(),
      }),
      idempotent: true,
      run: async ({ group, path_prefix }) => {
        const groups = matrix.groups.filter(
          (g) =>
            (!group || g.group.toLowerCase() === group.toLowerCase()) &&
            (!path_prefix || g.rows.some((r) => r.path.startsWith(path_prefix))),
        );
        if (!groups.length) return 'No resource groups match.';
        let rows = 0;
        const out: string[] = [];
        for (const g of groups) {
          if (rows >= MAX_ROWS) {
            out.push('(more groups not shown)');
            break;
          }
          const filtered = path_prefix ? { ...g, rows: g.rows.filter((r) => r.path.startsWith(path_prefix)) } : g;
          out.push(renderGroup(filtered));
          rows += filtered.rows.length;
        }
        return out.join('\n\n');
      },
    }),
    defineTool({
      name: 'data_access_sites',
      description:
        'Data-access calls (ORM, query builder, raw SQL) found by name in the code index, with whether the statement text scopes the query by the current user or tenant (scope=user|tenant|none|unknown). Lexical evidence to read and confirm; a filter applied elsewhere is invisible here.',
      input: z.strictObject({
        path_prefix: z.string().optional(),
        scoped_by: z.enum(['user', 'tenant', 'none', 'unknown']).optional(),
      }),
      idempotent: true,
      run: async ({ path_prefix, scoped_by }) => {
        const sites = matrix.sites.filter(
          (s) => (!path_prefix || s.path.startsWith(path_prefix)) && (!scoped_by || s.scopedBy === scoped_by),
        );
        if (!sites.length) return 'No data-access sites match.';
        return sites
          .slice(0, MAX_SITES)
          .map(
            (s) =>
              `${s.path}:${s.line} ${s.callee} [${s.orm}, ${s.operation}] scope=${s.scopedBy}${s.scopeTokens.length ? ` (${s.scopeTokens.join(', ')})` : ''} in ${s.callerKey}`,
          )
          .join('\n')
          .concat(sites.length > MAX_SITES ? `\n(+${sites.length - MAX_SITES} more)` : '');
      },
    }),
  ];
  return tools as unknown as AgentTool<never>[];
}

export type { DataAccessScope };
