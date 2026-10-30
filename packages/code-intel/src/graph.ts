import { dirname, posix } from 'node:path';
import { classifyControl, lastSegment } from './extractors/common';
import type {
  CallEdge,
  CodeIndexData,
  ControlRef,
  Endpoint,
  FileExtraction,
  GlobalControl,
  SymbolRecord,
} from './types';

export interface AuthContext {
  endpoint: Endpoint;
  handlers: SymbolRecord[];
  /** Controls in evaluation order: global, router-level, inline/decorator. Resolved symbol when found. */
  controls: Array<ControlRef & { symbol?: SymbolRecord }>;
  hasAuthentication: boolean;
  hasAuthorization: boolean;
}

export interface SymbolQuery {
  name?: string;
  path?: string;
  kind?: SymbolRecord['kind'];
  limit?: number;
}

/**
 * In-memory view over an index: symbol lookup, call graph, endpoints with mount prefixes and
 * security controls. Resolution is best-effort (ADR: confidence recorded on each edge).
 */
export class CodeGraph {
  readonly symbols = new Map<string, SymbolRecord>();
  readonly files = new Map<string, FileExtraction>();
  readonly edges: CallEdge[];
  private readonly outgoing = new Map<string, CallEdge[]>();
  private readonly incoming = new Map<string, CallEdge[]>();
  private readonly byName = new Map<string, SymbolRecord[]>();
  private readonly endpointList: Endpoint[];

  constructor(readonly data: CodeIndexData) {
    for (const file of data.files) {
      this.files.set(file.path, file);
      for (const symbol of file.symbols) {
        this.symbols.set(symbol.key, symbol);
        const list = this.byName.get(symbol.name) ?? [];
        list.push(symbol);
        this.byName.set(symbol.name, list);
      }
    }
    this.edges = data.edges;
    for (const edge of data.edges) {
      (this.outgoing.get(edge.from) ?? this.outgoing.set(edge.from, []).get(edge.from))?.push(edge);
      (this.incoming.get(edge.to) ?? this.incoming.set(edge.to, []).get(edge.to))?.push(edge);
    }
    this.endpointList = resolveMounts(data.files);
  }

  getSymbol(key: string): SymbolRecord | undefined {
    return this.symbols.get(key);
  }

  search(query: SymbolQuery): SymbolRecord[] {
    const limit = query.limit ?? 50;
    const out: SymbolRecord[] = [];
    for (const symbol of this.symbols.values()) {
      if (symbol.kind === 'module') continue;
      if (query.kind && symbol.kind !== query.kind) continue;
      if (query.path && !symbol.path.startsWith(query.path)) continue;
      if (query.name && !symbol.qualifiedName.toLowerCase().includes(query.name.toLowerCase())) continue;
      out.push(symbol);
      if (out.length >= limit) break;
    }
    return out;
  }

  /** Smallest symbol containing a line. */
  symbolAt(path: string, line: number): SymbolRecord | undefined {
    let best: SymbolRecord | undefined;
    for (const symbol of this.files.get(path)?.symbols ?? []) {
      if (symbol.kind === 'module' || symbol.startLine > line || symbol.endLine < line) continue;
      if (!best || symbol.endLine - symbol.startLine <= best.endLine - best.startLine) best = symbol;
    }
    return best;
  }

  callees(key: string): CallEdge[] {
    return this.outgoing.get(key) ?? [];
  }

  callers(key: string): CallEdge[] {
    return this.incoming.get(key) ?? [];
  }

  /** Transitive callers up to `depth` hops, with the hop at which each was reached. */
  transitiveCallers(keys: Iterable<string>, depth = 4): Map<string, number> {
    const seen = new Map<string, number>();
    let frontier = [...keys];
    for (let hop = 1; hop <= depth && frontier.length; hop++) {
      const next: string[] = [];
      for (const key of frontier) {
        for (const edge of this.callers(key)) {
          if (seen.has(edge.from)) continue;
          seen.set(edge.from, hop);
          next.push(edge.from);
        }
      }
      frontier = next;
    }
    return seen;
  }

  endpoints(filter: { path?: string; method?: string; route?: string } = {}): Endpoint[] {
    return this.endpointList.filter(
      (e) =>
        (!filter.path || e.path.startsWith(filter.path)) &&
        (!filter.method || e.method === filter.method.toUpperCase()) &&
        (!filter.route || e.route.includes(filter.route)),
    );
  }

  endpoint(id: string): Endpoint | undefined {
    return this.endpointList.find((e) => e.id === id);
  }

  /** Endpoints whose handler chain or controls include any of the given symbols. */
  endpointsReaching(keys: ReadonlySet<string>): Endpoint[] {
    return this.endpointList.filter(
      (e) => e.handlers.some((h) => keys.has(h)) || e.controls.some((c) => keys.has(c.ref)),
    );
  }

  authContext(endpointId: string): AuthContext | undefined {
    const endpoint = this.endpoint(endpointId);
    if (!endpoint) return undefined;
    const file = this.files.get(endpoint.path);
    const controls: AuthContext['controls'] = [];
    const push = (control: ControlRef) => {
      const symbol = this.resolveRef(control.ref, endpoint.path);
      controls.push({ ...control, ...(symbol ? { ref: symbol.key, symbol } : {}) });
    };
    // Global middleware registered in the same file before the route (app.use(auth)).
    for (const g of file?.globalControls ?? []) {
      if (g.line < endpoint.line && (!g.mountPath || endpoint.route.startsWith(g.mountPath))) {
        push({ ref: g.ref, name: g.name, kind: g.kind, source: 'global', path: g.path, line: g.line });
      }
    }
    // Middleware registered where this file's router is mounted (app.use('/api', auth, usersRouter)).
    for (const other of this.files.values()) {
      if (other.path === endpoint.path) continue;
      for (const mount of other.mounts) {
        if (!this.mountTargets(other, mount.target).includes(endpoint.path)) continue;
        for (const g of other.globalControls) {
          if (
            g.line <= mount.line &&
            (!g.mountPath || mount.prefix.startsWith(g.mountPath) || g.mountPath === mount.prefix)
          ) {
            push({ ref: g.ref, name: g.name, kind: g.kind, source: 'router', path: g.path, line: g.line });
          }
        }
      }
    }
    for (const c of endpoint.controls) push(c);
    const handlers = endpoint.handlers
      .map((h) => this.resolveRef(h, endpoint.path) ?? this.symbols.get(h))
      .filter((s): s is SymbolRecord => !!s);
    return {
      endpoint,
      handlers,
      controls,
      hasAuthentication: controls.some((c) => c.kind === 'AUTHENTICATION'),
      hasAuthorization: controls.some((c) => c.kind === 'AUTHORIZATION'),
    };
  }

  /**
   * Resolves a name as written in `fromPath` to a symbol: local symbol, import binding, injected
   * field type (this.service.method), then a unique name in the same language. Dotted references
   * whose head cannot be resolved get no edge rather than a guessed one.
   */
  resolveRef(ref: string, fromPath: string, fromSymbol?: string): SymbolRecord | undefined {
    if (this.symbols.has(ref)) return this.symbols.get(ref);
    const file = this.files.get(fromPath);
    const name = lastSegment(ref);
    const segments = ref.split('.');
    const head = segments[0] ?? ref;
    const owner = fromSymbol ? this.symbols.get(fromSymbol)?.owner : undefined;
    if (owner && head === 'this' && segments.length === 2) {
      return this.files.get(fromPath)?.symbols.find((s) => s.owner === owner && s.name === name);
    }
    // Injected or declared field of the enclosing class: this.svc.find(...) or svc.find(...).
    const fieldName = head === 'this' ? segments[1] : head;
    if (owner && fieldName && segments.length === (head === 'this' ? 3 : 2)) {
      const field = file?.fieldTypes?.find((f) => f.owner === owner && f.field === fieldName);
      if (field) {
        const cls = this.resolveRef(field.type, fromPath);
        return cls ? this.files.get(cls.path)?.symbols.find((s) => s.owner === cls.key && s.name === name) : undefined;
      }
    }
    const local = file?.symbols.find((s) => s.name === ref || s.qualifiedName === ref);
    if (local) return local;
    for (const imp of file?.imports ?? []) {
      const binding = imp.names.find((n) => n.local === head || n.local === ref);
      if (!binding) continue;
      const target = resolveModule(fromPath, imp.specifier, this.files);
      if (!target) continue;
      const wanted =
        binding.imported === 'default' || binding.imported === '*' ? name : head === ref ? binding.imported : name;
      const found =
        this.files.get(target)?.symbols.find((s) => s.name === wanted && s.kind !== 'module') ??
        (binding.imported === 'default'
          ? this.files.get(target)?.symbols.find((s) => s.exported && s.kind !== 'module')
          : undefined);
      if (found) return found;
    }
    if (segments.length > 1) return undefined;
    const family = languageFamily(file?.language);
    const candidates = (this.byName.get(name) ?? []).filter(
      (s) => s.kind !== 'module' && languageFamily(this.files.get(s.path)?.language) === family,
    );
    return candidates.length === 1 ? candidates[0] : undefined;
  }

  private mountTargets(file: FileExtraction, target: string): string[] {
    const head = target.split('.')[0] ?? target;
    const imp = file.imports.find((i) => i.names.some((n) => n.local === head));
    if (!imp) return [];
    const resolved = resolveModule(file.path, imp.specifier, this.files);
    return resolved ? [resolved] : [];
  }
}

/** Builds call edges by resolving each call site against the symbol table. */
export function buildEdges(files: readonly FileExtraction[]): CallEdge[] {
  const graph = new CodeGraph({ version: 1, extractorVersion: '', files: [...files], edges: [] });
  const edges: CallEdge[] = [];
  const seen = new Set<string>();
  for (const file of files) {
    for (const call of file.calls) {
      const resolved = graph.resolveRef(call.callee, file.path, call.callerKey);
      if (!resolved || resolved.kind === 'module') continue;
      const key = `${call.callerKey}->${resolved.key}@${call.line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const sameFile = resolved.path === file.path;
      const direct = call.callee === call.name || call.callee.startsWith('this.');
      edges.push({
        from: call.callerKey,
        to: resolved.key,
        path: file.path,
        line: call.line,
        confidence: sameFile || direct ? 'HIGH' : 'MEDIUM',
      });
    }
  }
  return edges;
}

const JS_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '/index.ts', '/index.js', '/index.tsx'];

export function resolveModule(
  fromPath: string,
  specifier: string,
  files: ReadonlyMap<string, FileExtraction>,
): string | undefined {
  if (specifier.startsWith('.')) {
    const base = posix.normalize(posix.join(dirname(fromPath), specifier));
    const candidates = [
      base,
      ...JS_EXTENSIONS.map((ext) => base.replace(/\.(js|mjs|cjs)$/, '') + ext),
      ...JS_EXTENSIONS.map((ext) => base + ext),
    ];
    return candidates.find((c) => files.has(c));
  }
  // Python dotted module relative to any root: "app.services.orders" -> app/services/orders.py
  if (/^[\w.]+$/.test(specifier) && !specifier.includes('/')) {
    const rel = specifier.replace(/^\.+/, '').replace(/\./g, '/');
    for (const path of files.keys()) {
      if (
        path === `${rel}.py` ||
        path.endsWith(`/${rel}.py`) ||
        path === `${rel}/__init__.py` ||
        path.endsWith(`/${rel}/__init__.py`)
      )
        return path;
      if (path.endsWith(`/${rel}.java`) || path === `${rel}.java`) return path;
    }
  }
  return undefined;
}

/** Applies app.use('/prefix', router) mounts to the routes declared in the mounted file. */
function resolveMounts(files: readonly FileExtraction[]): Endpoint[] {
  const byPath = new Map(files.map((f) => [f.path, f]));
  const prefixes = new Map<string, string[]>();
  for (const file of files) {
    for (const mount of file.mounts) {
      const head = mount.target.split('.')[0] ?? mount.target;
      const imp = file.imports.find((i) => i.names.some((n) => n.local === head));
      const target = imp ? resolveModule(file.path, imp.specifier, byPath) : undefined;
      if (target) prefixes.set(target, [...(prefixes.get(target) ?? []), mount.prefix]);
    }
  }
  const out: Endpoint[] = [];
  for (const file of files) {
    for (const endpoint of file.endpoints) {
      const mounted = prefixes.get(file.path);
      if (!mounted?.length || endpoint.framework === 'nestjs' || endpoint.framework === 'spring') {
        out.push(endpoint);
        continue;
      }
      for (const prefix of mounted) {
        const route = `${prefix.replace(/\/+$/, '')}/${endpoint.route.replace(/^\/+/, '')}`.replace(/\/+$/, '') || '/';
        out.push({ ...endpoint, route, mountedAt: prefix });
      }
    }
  }
  return out;
}

export function controlKindOf(name: string): GlobalControl['kind'] {
  return classifyControl(name);
}

function languageFamily(language: string | undefined): string {
  return language === 'python' || language === 'java' ? language : 'js';
}
