import type { CodeGraph } from './graph';
import type { Endpoint, SymbolRecord } from './types';

export interface ImpactReport {
  changedFiles: string[];
  changedSymbols: string[];
  /** Symbols reached by walking callers from the changed symbols (key -> hop distance). */
  affectedSymbols: Record<string, number>;
  affectedEndpoints: Array<Pick<Endpoint, 'id' | 'method' | 'route' | 'path' | 'line'>>;
  /** Changed symbols that act as security controls on some endpoint. */
  affectedControls: string[];
  /** Files scanners should analyse: changed files plus files of affected symbols and endpoints. */
  scope: string[];
  /** True when a security control changed, so every endpoint it protects is in scope. */
  requiresExtendedScan: boolean;
}

/**
 * Change impact (docs/architecture/02 section 5.4): changed symbols are those whose content hash
 * differs between the baseline and current index; callers are followed up to `depth` hops; an
 * endpoint is affected when its handler chain or one of its controls is affected.
 */
export function computeImpact(
  base: CodeGraph | undefined,
  current: CodeGraph,
  changedFiles: readonly string[],
  depth = 4,
): ImpactReport {
  const changed = new Set<string>();
  for (const path of changedFiles) {
    const now = current.files.get(path)?.symbols ?? [];
    const before = new Map((base?.files.get(path)?.symbols ?? []).map((s) => [s.key, s]));
    for (const symbol of now) {
      if (symbol.kind === 'module') continue;
      const prev = before.get(symbol.key);
      if (!prev || prev.contentHash !== symbol.contentHash) changed.add(symbol.key);
      before.delete(symbol.key);
    }
    for (const [removed, symbol] of before) if (symbol.kind !== 'module') changed.add(removed);
    // A file without symbols (config, template) still counts as changed.
    if (now.length <= 1 && !base?.files.has(path)) changed.add(`${path}::<module>`);
  }
  const affected = current.transitiveCallers(changed, depth);
  const all = new Set<string>([...changed, ...affected.keys()]);
  const controls = new Set<string>();
  for (const endpoint of current.endpoints()) {
    for (const control of endpoint.controls) {
      const key = current.resolveRef(control.ref, endpoint.path)?.key ?? control.ref;
      if (all.has(key)) controls.add(key);
    }
  }
  for (const file of current.files.values()) {
    for (const g of file.globalControls) {
      const resolved = current.resolveRef(g.ref, file.path);
      if (resolved && all.has(resolved.key)) controls.add(resolved.key);
    }
  }
  const endpoints = current.endpoints().filter((e) => {
    if (e.handlers.some((h) => all.has(h) || all.has(current.resolveRef(h, e.path)?.key ?? ''))) return true;
    const ctx = current.authContext(e.id);
    return ctx?.controls.some((c) => all.has(c.ref)) ?? false;
  });
  const scope = new Set<string>(changedFiles);
  for (const key of all) {
    const symbol: SymbolRecord | undefined = current.getSymbol(key);
    if (symbol) scope.add(symbol.path);
  }
  for (const e of endpoints) scope.add(e.path);
  return {
    changedFiles: [...changedFiles].sort(),
    changedSymbols: [...changed].sort(),
    affectedSymbols: Object.fromEntries([...affected.entries()].sort()),
    affectedEndpoints: endpoints.map((e) => ({
      id: e.id,
      method: e.method,
      route: e.route,
      path: e.path,
      line: e.line,
    })),
    affectedControls: [...controls].sort(),
    scope: [...scope].sort(),
    requiresExtendedScan: controls.size > 0,
  };
}
