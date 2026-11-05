import type { CodeEndpoint, CodeGraphView, SourceTree } from '../ports';
import { type DataAccessSite, extractDataAccessSites } from './data-access';

/**
 * Resource × operation matrix (ADR-049): endpoints grouped by the resource they act on, each with
 * the controls code-intel detected and whether the handler takes an object identifier. Rows where a
 * sibling carries an authorization control (or a user/tenant-scoped query) and this one does not
 * are flagged for the auditor to read. The matrix is a worksheet, never a finding: control detection
 * is name-based and a service-layer check is invisible to it.
 */
export interface MatrixControls {
  authn: string[];
  authz: string[];
  validation: string[];
  rateLimit: string[];
}

export interface MatrixRow {
  endpointId: string;
  method: string;
  route: string;
  path: string;
  line: number;
  handler?: { key: string; path: string; startLine: number; endLine: number };
  controls: MatrixControls;
  /** The route or handler reads an object identifier from the request. */
  identifierParam: boolean;
  identifierTokens: string[];
  dataAccess: DataAccessSite[];
  /** Heuristic: a sibling in the group has authorization or a scoped query and this row has neither. */
  flagged: boolean;
}

export interface ResourceGroup {
  /** Controller class or route noun. */
  group: string;
  rows: MatrixRow[];
  flaggedCount: number;
}

export interface ResourceMatrix {
  groups: ResourceGroup[];
  sites: DataAccessSite[];
  stats: { endpoints: number; groups: number; flagged: number; dataAccessSites: number };
}

const ID_PARAM = /(:\w*id\w*|:\w+|\{\w+\}|<[^>]+>)/i;
const ID_IN_BODY =
  /\b(req\.params|request\.params|params\[|\.params\.|@Param\(|request\.args|request\.view_args|@PathVariable|@RequestParam|ctx\.params|event\.pathParameters)\b/;

function routeNoun(route: string): string {
  const segments = route
    .split('/')
    .filter(Boolean)
    .filter((s) => !/^(api|v\d+)$/i.test(s));
  const noun = segments.find((s) => !/^[:{<]/.test(s) && !/^\d+$/.test(s));
  return noun ?? '(root)';
}

function hasScopedAccess(row: Pick<MatrixRow, 'dataAccess'>): boolean {
  return row.dataAccess.some((d) => d.scopedBy === 'user' || d.scopedBy === 'tenant');
}

export async function buildResourceMatrix(
  graph: CodeGraphView,
  source: SourceTree,
  paths: readonly string[],
): Promise<ResourceMatrix> {
  const endpoints = graph.endpoints();
  const sites = await extractDataAccessSites(graph, source, paths);
  const sitesByPath = new Map<string, DataAccessSite[]>();
  for (const s of sites) sitesByPath.set(s.path, [...(sitesByPath.get(s.path) ?? []), s]);
  const textCache = new Map<string, string[] | undefined>();
  const linesOf = async (path: string) => {
    if (!textCache.has(path)) textCache.set(path, (await source.readText(path))?.split(/\r?\n/));
    return textCache.get(path);
  };
  const inRange = (s: DataAccessSite, h: { path: string; startLine: number; endLine: number }) =>
    s.path === h.path && s.line >= h.startLine && s.line <= h.endLine;

  const groups = new Map<string, MatrixRow[]>();
  for (const e of endpoints) {
    const ctx = graph.authContext(e.id);
    const controls: MatrixControls = { authn: [], authz: [], validation: [], rateLimit: [] };
    for (const c of ctx?.controls ?? e.controls) {
      if (c.kind === 'AUTHENTICATION') controls.authn.push(c.name);
      else if (c.kind === 'AUTHORIZATION') controls.authz.push(c.name);
      else if (c.kind === 'VALIDATION') controls.validation.push(c.name);
      else if (c.kind === 'RATE_LIMIT') controls.rateLimit.push(c.name);
    }
    const final = ctx?.handlers.at(-1);
    const handler = final
      ? { key: final.key, path: final.path, startLine: final.startLine, endLine: final.endLine }
      : undefined;
    const identifierTokens: string[] = [];
    const routeId = ID_PARAM.exec(e.route);
    if (routeId) identifierTokens.push(routeId[0]);
    if (handler) {
      const lines = await linesOf(handler.path);
      const body = lines?.slice(handler.startLine - 1, handler.endLine).join('\n') ?? '';
      const bodyId = ID_IN_BODY.exec(body);
      if (bodyId) identifierTokens.push(bodyId[0]);
    }
    const dataAccess: DataAccessSite[] = [];
    if (handler) {
      dataAccess.push(...(sitesByPath.get(handler.path) ?? []).filter((s) => inRange(s, handler)));
      for (const edge of graph.callees(handler.key)) {
        const callee = graph.getSymbol(edge.to);
        if (!callee) continue;
        dataAccess.push(...(sitesByPath.get(callee.path) ?? []).filter((s) => inRange(s, callee)));
      }
    }
    const row: MatrixRow = {
      endpointId: e.id,
      method: e.method,
      route: e.route,
      path: e.path,
      line: e.line,
      ...(handler ? { handler } : {}),
      controls,
      identifierParam: identifierTokens.length > 0,
      identifierTokens,
      dataAccess,
      flagged: false,
    };
    const key = groupKey(e, final?.owner);
    groups.set(key, [...(groups.get(key) ?? []), row]);
  }

  const result: ResourceGroup[] = [];
  let flagged = 0;
  for (const [group, rows] of groups) {
    const protectedSibling = rows.some((r) => r.controls.authz.length > 0 || hasScopedAccess(r));
    for (const r of rows) {
      r.flagged = protectedSibling && r.identifierParam && r.controls.authz.length === 0 && !hasScopedAccess(r);
      if (r.flagged) flagged++;
    }
    rows.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line);
    result.push({ group, rows, flaggedCount: rows.filter((r) => r.flagged).length });
  }
  result.sort(
    (a, b) => b.flaggedCount - a.flaggedCount || b.rows.length - a.rows.length || a.group.localeCompare(b.group),
  );
  return {
    groups: result,
    sites,
    stats: { endpoints: endpoints.length, groups: result.length, flagged, dataAccessSites: sites.length },
  };
}

function groupKey(e: CodeEndpoint, owner: string | undefined): string {
  if (owner) return owner.split('::').pop() ?? owner;
  return routeNoun(e.route);
}
