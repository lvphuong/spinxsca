import type { CodeGraphView, DependencyUsageInfo } from '@spinxsca/core';

/** PyPI distributions whose import name differs from the package name. */
const PYPI_MODULES: Readonly<Record<string, string[]>> = {
  pyyaml: ['yaml'],
  beautifulsoup4: ['bs4'],
  pillow: ['PIL'],
  'python-dateutil': ['dateutil'],
  'scikit-learn': ['sklearn'],
  'opencv-python': ['cv2'],
  pyjwt: ['jwt'],
  protobuf: ['google.protobuf'],
  'python-jose': ['jose'],
  pycryptodome: ['Crypto'],
  'msgpack-python': ['msgpack'],
  setuptools: ['setuptools', 'pkg_resources'],
};

/** Maven coordinates whose Java packages do not start with the group id. */
const MAVEN_PACKAGES: Readonly<Record<string, string[]>> = {
  'com.fasterxml.jackson.core:jackson-databind': ['com.fasterxml.jackson.databind'],
  'com.fasterxml.jackson.core:jackson-core': ['com.fasterxml.jackson.core'],
  'org.apache.logging.log4j:log4j-core': ['org.apache.logging.log4j'],
  'org.apache.logging.log4j:log4j-api': ['org.apache.logging.log4j'],
  'org.yaml:snakeyaml': ['org.yaml.snakeyaml'],
  'org.apache.commons:commons-text': ['org.apache.commons.text'],
  'org.apache.commons:commons-lang3': ['org.apache.commons.lang3'],
  'commons-collections:commons-collections': ['org.apache.commons.collections'],
};

export function importMatcher(ecosystem: string, name: string): (specifier: string) => boolean {
  const eco = ecosystem.toLowerCase();
  if (eco === 'npm') return (s) => s === name || s.startsWith(`${name}/`) || s === `node:${name}`;
  if (eco === 'pypi') {
    const n = name.toLowerCase();
    const modules = PYPI_MODULES[n] ?? [n.replace(/-/g, '_')];
    return (s) => modules.some((m) => s === m || s.startsWith(`${m}.`));
  }
  if (eco === 'maven') {
    const [group = '', artifact = ''] = name.split(':');
    const prefixes = MAVEN_PACKAGES[name] ?? [`${group}.${artifact.replace(/-/g, '.')}`, group];
    return (s) => prefixes.some((p) => s === p || s.startsWith(`${p}.`));
  }
  return () => false;
}

/**
 * Dependency reachability over the code index (ADR-043): where the package is imported, which calls
 * use the imported bindings (narrowed to the vulnerable symbols when known), and whether an endpoint
 * reaches those calls. Syntactic, without dataflow: the level is a ceiling for what the static index
 * can show, and the confidence says how much of it rests on symbol names.
 */
export function dependencyUsage(
  graph: CodeGraphView,
  input: {
    ecosystem: string;
    name: string;
    symbols?: readonly string[];
    symbolSource?: 'advisory' | 'model';
    /** From the lockfile: true when the project declares the package itself. */
    direct?: boolean;
  },
): DependencyUsageInfo {
  if (!graph.importsOf || !graph.callSitesIn || !graph.filePaths) {
    return {
      level: 'UNKNOWN_TRANSITIVE',
      confidence: 'LOW',
      symbolSource: 'none',
      importSites: [],
      callSites: [],
      entrypoints: [],
      detail: 'the code index does not expose imports',
    };
  }
  const matches = importMatcher(input.ecosystem, input.name);
  const symbols = new Set((input.symbols ?? []).map((s) => s.split('.').pop() as string).filter(Boolean));
  const symbolSource = symbols.size ? (input.symbolSource ?? 'model') : 'none';
  const importSites: DependencyUsageInfo['importSites'] = [];
  const callSites: DependencyUsageInfo['callSites'] = [];
  const callers = new Set<string>();
  for (const path of graph.filePaths()) {
    const imports = graph.importsOf(path).filter((i) => matches(i.specifier));
    if (imports.length === 0) continue;
    const bindings = new Map<string, string>();
    for (const imp of imports) {
      importSites.push({ path, line: imp.line, specifier: imp.specifier });
      for (const n of imp.names) bindings.set(n.local, n.imported);
    }
    for (const call of graph.callSitesIn(path)) {
      const head = call.callee.split('.')[0] as string;
      const imported = bindings.get(head);
      if (imported === undefined) continue;
      // `_.template(...)` has name "template"; a named import `{ template }` is called as "template".
      const member = call.callee.includes('.')
        ? call.name
        : imported === 'default' || imported === '*'
          ? call.name
          : imported;
      if (symbols.size && !symbols.has(member)) continue;
      callSites.push({ path, line: call.line, callee: call.callee });
      if (call.callerKey && !call.callerKey.endsWith('::<module>')) callers.add(call.callerKey);
    }
  }
  const reached = new Set<string>([...callers, ...collectTransitive(graph, callers, 6)]);
  // Handlers are symbol keys when resolved, otherwise names as written in the route file.
  const reachedNames = new Set([...reached].map((k) => k.slice(k.lastIndexOf('::') + 2)));
  const hits = (e: { path: string }, ref: string) =>
    reached.has(ref) || reached.has(`${e.path}::${ref}`) || reachedNames.has(ref.split('.').pop() as string);
  const entrypoints = graph
    .endpoints()
    .filter((e) => e.handlers.some((h) => hits(e, h)) || e.controls.some((c) => hits(e, c.ref)))
    .map((e) => ({ id: e.id, method: e.method, route: e.route, path: e.path, line: e.line }));
  const confidence: DependencyUsageInfo['confidence'] = symbols.size
    ? symbolSource === 'advisory'
      ? 'HIGH'
      : 'MEDIUM'
    : 'LOW';
  if (importSites.length === 0) {
    return {
      level: input.direct === false ? 'UNKNOWN_TRANSITIVE' : 'NOT_IMPORTED',
      confidence: input.direct === false ? 'LOW' : 'MEDIUM',
      symbolSource,
      importSites,
      callSites,
      entrypoints,
      detail:
        input.direct === false
          ? 'not imported by project code; a dependency of another package may still call it'
          : 'no import of the package in the indexed code',
    };
  }
  if (callSites.length === 0) {
    return {
      level: 'IMPORTED_ONLY',
      confidence,
      symbolSource,
      importSites,
      callSites,
      entrypoints,
      detail: symbols.size
        ? `imported, but none of ${[...symbols].join(', ')} is called on the imported bindings`
        : 'imported, but no call on the imported bindings was found',
    };
  }
  return {
    level: entrypoints.length ? 'CALLED_FROM_ENTRYPOINT' : 'CALLED',
    confidence,
    symbolSource,
    importSites,
    callSites,
    entrypoints,
    detail: entrypoints.length
      ? `${callSites.length} call(s) reachable from ${entrypoints.map((e) => `${e.method} ${e.route}`).join(', ')}`
      : `${callSites.length} call(s); no endpoint reaches them in the index`,
  };
}

function collectTransitive(graph: CodeGraphView, keys: Iterable<string>, depth: number): Set<string> {
  const seen = new Set<string>();
  let frontier = [...keys];
  for (let hop = 0; hop < depth && frontier.length; hop++) {
    const next: string[] = [];
    for (const key of frontier) {
      for (const edge of graph.callers(key)) {
        if (seen.has(edge.from)) continue;
        seen.add(edge.from);
        next.push(edge.from);
      }
    }
    frontier = next;
  }
  return seen;
}
