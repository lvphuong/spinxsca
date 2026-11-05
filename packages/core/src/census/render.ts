import type { DataAccessSite } from './data-access';
import type { ResourceGroup, ResourceMatrix } from './resource-matrix';

export const CENSUS_MARKER = '## CENSUS WORKSHEET';
const MIN_GROUP_SIZE = 2;
const MAX_FILES = 12;

const controlsOf = (r: ResourceGroup['rows'][number]) =>
  [
    r.controls.authn.length ? `authn: ${r.controls.authn.join(',')}` : '',
    r.controls.authz.length ? `authz: ${r.controls.authz.join(',')}` : '',
    r.controls.validation.length ? `validation: ${r.controls.validation.join(',')}` : '',
  ]
    .filter(Boolean)
    .join('; ') || 'no control detected';

const accessOf = (sites: readonly DataAccessSite[]) =>
  sites.length
    ? sites.map((s) => `${s.callee}@${s.line} ${s.operation} scope=${s.scopedBy}`).join(' | ')
    : 'no data access detected';

export function renderGroup(g: ResourceGroup): string {
  const lines = [`### ${g.group} (${g.rows.length} operations, ${g.flaggedCount} flagged)`];
  for (const r of g.rows) {
    lines.push(
      `- ${r.flagged ? '[!] ' : ''}${r.method} ${r.route} (${r.path}:${r.line}) id-param=${r.identifierParam ? r.identifierTokens.join('/') : 'no'}; ${controlsOf(r)}; ${accessOf(r.dataAccess)}`,
    );
  }
  return lines.join('\n');
}

/**
 * Deterministic worksheet injected into recon and audit prompts (Argo's census idea): the model
 * clears an enumerated list ("N operations in this group, these lack an authorization control")
 * instead of rediscovering the spread. Only groups with at least two operations are listed.
 */
export function renderCensus(matrix: ResourceMatrix, options: { maxChars?: number } = {}): string {
  const maxChars = options.maxChars ?? 4000;
  const groups = matrix.groups.filter((g) => g.rows.length >= MIN_GROUP_SIZE);
  if (!groups.length) return '';
  const header = [
    `${CENSUS_MARKER} (deterministic, heuristic, lower-bound; NOT findings)`,
    'Controls are classified by name and data-access scope by tokens in the statement; a check in a service layer or a policy object is invisible here. Treat every row as something to read, and the [!] marker as a sibling that lacks a control its siblings have.',
    `${matrix.stats.endpoints} endpoints in ${matrix.stats.groups} resource groups; ${matrix.stats.flagged} flagged rows; ${matrix.stats.dataAccessSites} data-access sites.`,
  ].join('\n');
  const parts: string[] = [header];
  let size = header.length;
  let files = 0;
  for (const g of groups) {
    const block = renderGroup(g);
    if (size + block.length > maxChars || files >= MAX_FILES) {
      parts.push(`(+${groups.length - files} more groups not shown)`);
      break;
    }
    parts.push(block);
    size += block.length;
    files++;
  }
  return parts.join('\n\n');
}

/** Compact JSON of the matrix for artifacts and the scripted test provider. */
export function censusJson(matrix: ResourceMatrix): string {
  return JSON.stringify({
    stats: matrix.stats,
    groups: matrix.groups.map((g) => ({
      group: g.group,
      rows: g.rows.map((r) => ({
        endpointId: r.endpointId,
        method: r.method,
        route: r.route,
        path: r.path,
        line: r.line,
        handler: r.handler,
        authz: r.controls.authz,
        authn: r.controls.authn,
        identifierParam: r.identifierParam,
        scoped: r.dataAccess.map((d) => d.scopedBy),
        flagged: r.flagged,
      })),
    })),
  });
}
