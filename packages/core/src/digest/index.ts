import type { Digest, DigestNode, RepoDigest, SnapshotFile } from '@spinxsca/schemas';
import type { DataAccessSite } from '../census/data-access';
import type { CodeGraphView } from '../ports';

export interface DigestInput {
  files: readonly SnapshotFile[];
  contentManifestDigest: Digest;
  graph?: CodeGraphView;
  sites?: readonly DataAccessSite[];
  /** Line counts per path when the caller has them; otherwise estimated from size. */
  loc?: ReadonlyMap<string, number>;
}

const ROOT = '';
const MAX_EXTERNAL = 12;
const MAX_TOP_ENDPOINTS = 6;

/**
 * Builds the repository digest (ADR-056) in one pass over the files, aggregating counts up the
 * directory tree. Deterministic: the same snapshot and index always give the same digest.
 */
export function buildRepoDigest(input: DigestInput): RepoDigest {
  const nodes = new Map<string, DigestNode & { imports: Map<string, number> }>();
  const node = (path: string, kind: 'dir' | 'file') => {
    let n = nodes.get(path);
    if (!n) {
      n = {
        path,
        kind,
        files: 0,
        loc: 0,
        bytes: 0,
        languages: {},
        endpoints: 0,
        controls: 0,
        dataAccess: 0,
        symbols: 0,
        externalImports: [],
        topEndpoints: [],
        children: [],
        imports: new Map(),
      };
      nodes.set(path, n);
    }
    return n;
  };
  const ancestors = (path: string): string[] => {
    const parts = path.split('/');
    parts.pop();
    const out = [ROOT];
    for (let i = 1; i <= parts.length; i++) out.push(parts.slice(0, i).join('/'));
    return out;
  };
  node(ROOT, 'dir');
  const endpointsByPath = new Map<string, string[]>();
  const controlsByPath = new Map<string, number>();
  for (const e of input.graph?.endpoints() ?? []) {
    endpointsByPath.set(e.path, [...(endpointsByPath.get(e.path) ?? []), `${e.method} ${e.route}`]);
    for (const c of e.controls) controlsByPath.set(c.path, (controlsByPath.get(c.path) ?? 0) + 1);
  }
  const sitesByPath = new Map<string, number>();
  for (const s of input.sites ?? []) sitesByPath.set(s.path, (sitesByPath.get(s.path) ?? 0) + 1);

  for (const file of [...input.files].sort((a, b) => a.path.localeCompare(b.path))) {
    const language = file.path.slice(file.path.lastIndexOf('.') + 1).toLowerCase();
    const loc = input.loc?.get(file.path) ?? Math.ceil(file.size / 40);
    const endpoints = endpointsByPath.get(file.path) ?? [];
    const controls = controlsByPath.get(file.path) ?? 0;
    const dataAccess = sitesByPath.get(file.path) ?? 0;
    const symbols = input.graph ? input.graph.search({ path: file.path, limit: 1_000 }).length : 0;
    const external = (input.graph?.importsOf?.(file.path) ?? [])
      .map((i) => i.specifier)
      .filter((s) => !s.startsWith('.') && !s.startsWith('/'))
      .map((s) => (s.startsWith('@') ? s.split('/').slice(0, 2).join('/') : (s.split('/')[0] as string)));
    const chain = ancestors(file.path);
    for (const [i, dir] of chain.entries()) {
      const n = node(dir, 'dir');
      n.files++;
      n.loc += loc;
      n.bytes += file.size;
      n.languages[language] = (n.languages[language] ?? 0) + 1;
      n.endpoints += endpoints.length;
      n.controls += controls;
      n.dataAccess += dataAccess;
      n.symbols += symbols;
      for (const x of external) n.imports.set(x, (n.imports.get(x) ?? 0) + 1);
      if (n.topEndpoints.length < MAX_TOP_ENDPOINTS)
        n.topEndpoints.push(...endpoints.slice(0, MAX_TOP_ENDPOINTS - n.topEndpoints.length));
      const child = chain[i + 1] ?? file.path;
      if (!n.children.includes(child)) n.children.push(child);
    }
  }
  const out: Record<string, DigestNode> = {};
  for (const [path, n] of nodes) {
    const { imports, ...rest } = n;
    out[path] = {
      ...rest,
      externalImports: [...imports.entries()]
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .slice(0, MAX_EXTERNAL)
        .map(([k]) => k),
      children: [...rest.children].sort(),
    };
  }
  const root = out[ROOT] as DigestNode;
  return {
    version: 1,
    contentManifestDigest: input.contentManifestDigest,
    root: ROOT,
    nodes: out,
    stats: { files: root.files, loc: root.loc, directories: Object.keys(out).length, endpoints: root.endpoints },
  };
}

export interface RenderDigestOptions {
  /** Subtree to render; the root when absent. */
  path?: string;
  /** Directory levels below `path` to expand (default 2). */
  depth?: number;
  maxChars?: number;
}

const k = (n: number) => (n >= 1000 ? `${(n / 1000).toFixed(n >= 10_000 ? 0 : 1)}k` : String(n));

function line(n: DigestNode): string {
  const langs = Object.entries(n.languages)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([l]) => l)
    .join(',');
  const parts = [`${n.path || '(root)'}/ ${n.files} files ${k(n.loc)} LOC${langs ? ` ${langs}` : ''}`];
  if (n.endpoints)
    parts.push(
      `${n.endpoints} endpoints${n.topEndpoints.length ? ` (${n.topEndpoints.slice(0, 3).join(', ')}${n.endpoints > 3 ? ' …' : ''})` : ''}`,
    );
  if (n.controls) parts.push(`controls ${n.controls}`);
  if (n.dataAccess) parts.push(`data access ${n.dataAccess}`);
  if (n.externalImports.length) parts.push(`imports ${n.externalImports.slice(0, 5).join(', ')}`);
  if (n.summary) parts.push(n.summary);
  return parts.join(' | ');
}

/**
 * Renders a subtree as an indented list, largest directories first, cut to `maxChars`. Files are
 * listed only at the deepest expanded level and only when the directory has few of them.
 */
export function renderDigest(digest: RepoDigest, options: RenderDigestOptions = {}): string {
  const start = options.path?.replace(/\/+$/, '') ?? digest.root;
  const depth = options.depth ?? 2;
  const maxChars = options.maxChars ?? 10_000;
  const root = digest.nodes[start];
  if (!root) return `No directory ${start} in the repository digest.`;
  const lines: string[] = [];
  const walk = (n: DigestNode, level: number) => {
    lines.push(`${'  '.repeat(level)}- ${line(n)}`);
    if (level >= depth) {
      if (n.children.length)
        lines.push(
          `${'  '.repeat(level + 1)}(${n.children.length} entries; call repo_map with path="${n.path}" to expand)`,
        );
      return;
    }
    const dirs = n.children.filter((c) => digest.nodes[c]).map((c) => digest.nodes[c] as DigestNode);
    const files = n.children.filter((c) => !digest.nodes[c]);
    for (const d of [...dirs].sort((a, b) => b.loc - a.loc || a.path.localeCompare(b.path))) walk(d, level + 1);
    if (files.length && files.length <= 12) for (const f of files) lines.push(`${'  '.repeat(level + 1)}- ${f}`);
    else if (files.length) lines.push(`${'  '.repeat(level + 1)}(${files.length} files)`);
  };
  walk(root, 0);
  let body = lines.join('\n');
  if (body.length > maxChars) body = `${body.slice(0, maxChars - 40)}\n… (digest truncated; use repo_map)`;
  return `Repository digest (${digest.stats.files} files, ${k(digest.stats.loc)} LOC, ${digest.stats.endpoints} endpoints):\n${body}`;
}
