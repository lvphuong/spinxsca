import type { CodeGraphView } from '@spinxsca/core';
import { z } from 'zod';
import { type AgentTool, defineTool } from '../runtime/tools';

const MAX = 40;

/** Code intelligence tools (docs/architecture/03 section 5): symbol lookup, call graph, endpoints, auth context. */
export function createGraphTools(graph: CodeGraphView): AgentTool<never>[] {
  const fmtSymbol = (key: string): string => {
    const s = graph.getSymbol(key);
    return s ? `${s.key} (${s.kind}, ${s.path}:${s.startLine}-${s.endLine})` : key;
  };
  const tools = [
    defineTool({
      name: 'list_endpoints',
      description:
        'List HTTP endpoints discovered in the code with their controls (middleware, guards, dependencies, annotations).',
      input: z.strictObject({
        path_prefix: z.string().optional(),
        route_contains: z.string().optional(),
        method: z.string().optional(),
      }),
      run: async ({ path_prefix, route_contains, method }) => {
        const endpoints = graph.endpoints({
          ...(path_prefix ? { path: path_prefix } : {}),
          ...(route_contains ? { route: route_contains } : {}),
          ...(method ? { method } : {}),
        });
        if (endpoints.length === 0) return 'No endpoints found.';
        return endpoints
          .slice(0, 200)
          .map((e) => {
            const ctx = graph.authContext(e.id);
            const controls = (ctx?.controls ?? [])
              .filter((c) => c.kind !== 'OTHER')
              .map((c) => `${c.name}:${c.kind.toLowerCase()}`);
            return `${e.id} | ${e.framework} | handlers: ${e.handlers.join(' -> ') || 'n/a'} | controls: ${controls.join(', ') || 'none detected'}`;
          })
          .join('\n');
      },
    }),
    defineTool({
      name: 'auth_context',
      description:
        'Authentication and authorization controls on the path to an endpoint (global middleware, router middleware, inline guards, decorators, dependencies), with their source locations.',
      input: z.strictObject({ endpoint_id: z.string().describe('id from list_endpoints') }),
      run: async ({ endpoint_id }) => {
        const ctx = graph.authContext(endpoint_id);
        if (!ctx) throw new Error(`unknown endpoint ${endpoint_id}`);
        const lines = [
          `${ctx.endpoint.method} ${ctx.endpoint.route} (${ctx.endpoint.path}:${ctx.endpoint.line})`,
          `handlers: ${ctx.handlers.map((h) => `${h.key} [${h.path}:${h.startLine}-${h.endLine}]`).join(' -> ') || 'unresolved'}`,
          `authentication detected: ${ctx.hasAuthentication}; authorization detected: ${ctx.hasAuthorization}`,
          'controls (heuristic classification by name; read the body to confirm what each enforces):',
          ...ctx.controls.map(
            (c) =>
              `  - ${c.name} [${c.kind.toLowerCase()}, ${c.source}] at ${c.path}:${c.line}${c.symbol ? ` -> ${c.symbol.key} (${c.symbol.path}:${c.symbol.startLine}-${c.symbol.endLine})` : ' (not resolved to a symbol)'}`,
          ),
        ];
        return lines.join('\n');
      },
    }),
    defineTool({
      name: 'get_symbol',
      description: 'Look up a function, method or class by key or by name; returns location and kind.',
      input: z.strictObject({
        key: z.string().optional(),
        name: z.string().optional(),
        path_prefix: z.string().optional(),
      }),
      run: async ({ key, name, path_prefix }) => {
        if (key) {
          const s = graph.getSymbol(key);
          return s ? fmtSymbol(s.key) : `No symbol ${key}.`;
        }
        const found = graph.search({
          ...(name ? { name } : {}),
          ...(path_prefix ? { path: path_prefix } : {}),
          limit: MAX,
        });
        return found.length ? found.map((s) => fmtSymbol(s.key)).join('\n') : 'No symbols match.';
      },
    }),
    defineTool({
      name: 'callers',
      description: 'Functions that call the given symbol (one hop).',
      input: z.strictObject({ key: z.string() }),
      run: async ({ key }) => {
        const edges = graph.callers(key);
        return edges.length
          ? edges
              .slice(0, MAX)
              .map((e) => `${fmtSymbol(e.from)} at ${e.path}:${e.line} [${e.confidence.toLowerCase()}]`)
              .join('\n')
          : 'No known callers (may be an entry point or called dynamically).';
      },
    }),
    defineTool({
      name: 'callees',
      description: 'Functions called by the given symbol (one hop, resolved calls only).',
      input: z.strictObject({ key: z.string() }),
      run: async ({ key }) => {
        const edges = graph.callees(key);
        return edges.length
          ? edges
              .slice(0, MAX)
              .map((e) => `${fmtSymbol(e.to)} at ${e.path}:${e.line} [${e.confidence.toLowerCase()}]`)
              .join('\n')
          : 'No resolved callees.';
      },
    }),
  ];
  return tools as unknown as AgentTool<never>[];
}
