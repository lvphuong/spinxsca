import { normalizeRelPath, type SourceTree } from '@spinxsca/core';
import { parse as parseYaml } from 'yaml';

export type DependencyScope = 'runtime' | 'development' | 'test' | 'unknown';

/** One resolved package of a lockfile, with how it got there (ADR-043). */
export interface DependencyRecord {
  ecosystem: 'npm' | 'PyPI' | 'Maven';
  name: string;
  version: string;
  manifestPath: string;
  /** Declared by the project itself (vs. pulled in by another package); undefined when unknown. */
  direct?: boolean;
  scope: DependencyScope;
  purl: string;
}

const LOCKFILES = [
  'package-lock.json',
  'npm-shrinkwrap.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'poetry.lock',
  'uv.lock',
  'pom.xml',
];
const REQUIREMENTS = /(^|\/)requirements[^/]*\.txt$/;

export function isDependencyManifest(path: string): boolean {
  const base = path.split('/').pop() ?? '';
  return LOCKFILES.includes(base) || REQUIREMENTS.test(path);
}

/**
 * Dependency inventory from lockfiles with direct/transitive and runtime/development scope, read
 * with the confinement of the source tree. Deterministic and offline: nothing is resolved.
 */
export async function parseLockfiles(source: SourceTree, paths: readonly string[]): Promise<DependencyRecord[]> {
  const out = new Map<string, DependencyRecord>();
  const add = (r: DependencyRecord) => {
    const key = `${r.ecosystem}|${r.name}|${r.version}|${r.manifestPath}`;
    const existing = out.get(key);
    // Runtime wins over development when the same package is reached both ways.
    if (!existing || (existing.scope !== 'runtime' && r.scope === 'runtime') || (r.direct && !existing.direct))
      out.set(key, r);
  };
  for (const raw of paths) {
    const path = normalizeRelPath(raw);
    if (!isDependencyManifest(path)) continue;
    const text = await source.readText(path);
    if (text === undefined) continue;
    const dir = path.includes('/') ? path.slice(0, path.lastIndexOf('/') + 1) : '';
    const base = path.slice(dir.length);
    try {
      let records: DependencyRecord[] = [];
      if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') records = npmLock(text, path);
      else if (base === 'pnpm-lock.yaml') records = pnpmLock(text, path);
      else if (base === 'yarn.lock') records = yarnLock(text, path, await source.readText(`${dir}package.json`));
      else if (base === 'poetry.lock' || base === 'uv.lock')
        records = pyLock(text, path, await source.readText(`${dir}pyproject.toml`));
      else if (base === 'pom.xml') records = pom(text, path);
      else if (REQUIREMENTS.test(path)) records = requirements(text, path);
      for (const r of records) add(r);
    } catch {
      // A malformed lockfile yields no records; the deterministic scanners report it as a tool error.
    }
  }
  return [...out.values()].sort((a, b) =>
    `${a.ecosystem}${a.name}${a.version}`.localeCompare(`${b.ecosystem}${b.name}${b.version}`),
  );
}

const npmPurl = (name: string, version: string) =>
  `pkg:npm/${name.startsWith('@') ? `%40${name.slice(1)}` : name}@${version}`;

function npmLock(text: string, path: string): DependencyRecord[] {
  const doc = JSON.parse(text) as {
    packages?: Record<
      string,
      {
        version?: string;
        dev?: boolean;
        optional?: boolean;
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
        optionalDependencies?: Record<string, string>;
        name?: string;
        link?: boolean;
      }
    >;
    dependencies?: Record<string, { version: string; dev?: boolean }>;
  };
  const out: DependencyRecord[] = [];
  if (doc.packages) {
    const root = doc.packages[''] ?? {};
    const directRuntime = new Set([
      ...Object.keys(root.dependencies ?? {}),
      ...Object.keys(root.optionalDependencies ?? {}),
    ]);
    const directDev = new Set(Object.keys(root.devDependencies ?? {}));
    for (const [key, pkg] of Object.entries(doc.packages)) {
      if (!key || !pkg.version || pkg.link) continue;
      const name = pkg.name ?? key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      const topLevel = key === `node_modules/${name}`;
      out.push({
        ecosystem: 'npm',
        name,
        version: pkg.version,
        manifestPath: path,
        direct: topLevel && (directRuntime.has(name) || directDev.has(name)),
        scope: pkg.dev ? 'development' : 'runtime',
        purl: npmPurl(name, pkg.version),
      });
    }
    return out;
  }
  const walk = (
    deps: Record<string, { version: string; dev?: boolean; dependencies?: Record<string, never> }>,
    depth: number,
  ) => {
    for (const [name, pkg] of Object.entries(deps)) {
      out.push({
        ecosystem: 'npm',
        name,
        version: pkg.version,
        manifestPath: path,
        ...(depth > 0 ? { direct: false } : {}),
        scope: pkg.dev ? 'development' : 'runtime',
        purl: npmPurl(name, pkg.version),
      });
      if (pkg.dependencies) walk(pkg.dependencies, depth + 1);
    }
  };
  walk((doc.dependencies ?? {}) as never, 0);
  return out;
}

function pnpmLock(text: string, path: string): DependencyRecord[] {
  const doc = parseYaml(text) as {
    importers?: Record<
      string,
      {
        dependencies?: Record<string, unknown>;
        devDependencies?: Record<string, unknown>;
        optionalDependencies?: Record<string, unknown>;
      }
    >;
    packages?: Record<string, { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string> }>;
    snapshots?: Record<
      string,
      { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string> }
    >;
  };
  const versionOf = (v: unknown) =>
    String(typeof v === 'object' && v ? (v as { version: string }).version : v).split('(')[0] as string;
  const graph = doc.snapshots ?? doc.packages ?? {};
  const keyOf = (name: string, version: string) =>
    [`${name}@${version}`, `/${name}@${version}`, `/${name}/${version}`].find((k) => k in graph) ??
    `${name}@${version}`;
  const scope = new Map<string, DependencyScope>();
  const direct = new Set<string>();
  const visit = (key: string, s: DependencyScope) => {
    if (scope.get(key) === 'runtime' || scope.get(key) === s) return;
    scope.set(key, s);
    const node = graph[key];
    for (const [n, v] of Object.entries({ ...node?.dependencies, ...node?.optionalDependencies }))
      visit(keyOf(n, versionOf(v)), s);
  };
  for (const importer of Object.values(doc.importers ?? {})) {
    for (const [n, v] of Object.entries({ ...importer.dependencies, ...importer.optionalDependencies })) {
      const k = keyOf(n, versionOf(v));
      direct.add(k);
      visit(k, 'runtime');
    }
    for (const [n, v] of Object.entries(importer.devDependencies ?? {})) {
      const k = keyOf(n, versionOf(v));
      direct.add(k);
      visit(k, 'development');
    }
  }
  const out: DependencyRecord[] = [];
  for (const key of Object.keys({ ...doc.packages, ...doc.snapshots })) {
    const m = /^\/?(@?[^@/]+(?:\/[^@/]+)?)[@/]([^(/]+)/.exec(key);
    if (!m) continue;
    const [, name, version] = m as unknown as [string, string, string];
    out.push({
      ecosystem: 'npm',
      name,
      version,
      manifestPath: path,
      direct: direct.has(key),
      scope: scope.get(key) ?? 'unknown',
      purl: npmPurl(name, version),
    });
  }
  return out;
}

function yarnLock(text: string, path: string, packageJson: string | undefined): DependencyRecord[] {
  const pkg = packageJson ? (JSON.parse(packageJson) as { dependencies?: object; devDependencies?: object }) : {};
  const runtime = new Set(Object.keys(pkg.dependencies ?? {}));
  const dev = new Set(Object.keys(pkg.devDependencies ?? {}));
  const out: DependencyRecord[] = [];
  for (const block of text.split(/\n(?=\S)/)) {
    const header = block.split('\n')[0] ?? '';
    const version = /\n\s+version:?\s+"?([^"\n]+)"?/.exec(block)?.[1];
    if (!version || header.startsWith('#') || header.startsWith('__metadata')) continue;
    const spec = header.split(',')[0]?.trim().replace(/^"|"$/g, '').replace(/:$/, '') ?? '';
    const name = spec.startsWith('@') ? `@${spec.slice(1).split('@')[0]}` : (spec.split('@')[0] ?? '');
    if (!name) continue;
    const isDirect = runtime.has(name) || dev.has(name);
    out.push({
      ecosystem: 'npm',
      name,
      version,
      manifestPath: path,
      direct: isDirect,
      scope: runtime.has(name) ? 'runtime' : dev.has(name) ? 'development' : 'unknown',
      purl: npmPurl(name, version),
    });
  }
  return out;
}

const pyName = (name: string) => name.toLowerCase().replace(/[-_.]+/g, '-');

/** Minimal TOML reading for [[package]] tables (name, version, category) of poetry.lock and uv.lock. */
function pyLock(text: string, path: string, pyproject: string | undefined): DependencyRecord[] {
  const declared = declaredPython(pyproject);
  const out: DependencyRecord[] = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const body = block.split(/^\[(?!\[package\])/m)[0] ?? block;
    const name = /^name\s*=\s*"([^"]+)"/m.exec(body)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(body)?.[1];
    if (!name || !version) continue;
    const category = /^category\s*=\s*"([^"]+)"/m.exec(body)?.[1];
    const n = pyName(name);
    const fromProject = declared.get(n);
    out.push({
      ecosystem: 'PyPI',
      name: n,
      version,
      manifestPath: path,
      ...(declared.size ? { direct: fromProject !== undefined } : {}),
      scope: fromProject ?? (category === 'dev' ? 'development' : category === 'main' ? 'runtime' : 'unknown'),
      purl: `pkg:pypi/${n}@${version}`,
    });
  }
  return out;
}

function declaredPython(pyproject: string | undefined): Map<string, DependencyScope> {
  const out = new Map<string, DependencyScope>();
  if (!pyproject) return out;
  let section = '';
  for (const line of pyproject.split('\n')) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (header) {
      section = header[1] as string;
      continue;
    }
    const devSection = /dev|test/.test(section);
    if (/^tool\.poetry(\.group\.[^.]+)?\.(dev-)?dependencies$/.test(section)) {
      const name = /^\s*([A-Za-z0-9_.-]+)\s*=/.exec(line)?.[1];
      if (name && name.toLowerCase() !== 'python') out.set(pyName(name), devSection ? 'development' : 'runtime');
    }
    if (section === 'project' || section === 'project.optional-dependencies' || section === 'dependency-groups') {
      for (const m of line.matchAll(/"([A-Za-z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*[<>=!~;]?[^"]*"/g)) {
        const scope: DependencyScope =
          section === 'project' && !/^\s*[a-z-]+\s*=\s*\[/.test(line)
            ? 'runtime'
            : devSection || section !== 'project'
              ? 'development'
              : 'runtime';
        if (!out.has(pyName(m[1] as string))) out.set(pyName(m[1] as string), scope);
      }
    }
  }
  return out;
}

function requirements(text: string, path: string): DependencyRecord[] {
  const scope: DependencyScope = /test/i.test(path) ? 'test' : /dev/i.test(path) ? 'development' : 'runtime';
  const out: DependencyRecord[] = [];
  for (const line of text.split('\n')) {
    const m = /^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.+!-]+)/.exec(line);
    if (!m) continue;
    const name = pyName(m[1] as string);
    out.push({
      ecosystem: 'PyPI',
      name,
      version: m[2] as string,
      manifestPath: path,
      direct: true,
      scope,
      purl: `pkg:pypi/${name}@${m[2]}`,
    });
  }
  return out;
}

function pom(text: string, path: string): DependencyRecord[] {
  const props = new Map<string, string>();
  const propsBlock = /<properties>([\s\S]*?)<\/properties>/.exec(text)?.[1] ?? '';
  for (const m of propsBlock.matchAll(/<([A-Za-z0-9_.-]+)>([^<]*)<\/\1>/g))
    props.set(m[1] as string, (m[2] as string).trim());
  const resolve = (v: string) => v.replace(/\$\{([^}]+)\}/g, (_m, k: string) => props.get(k) ?? `\${${k}}`);
  const body = text
    .replace(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/g, '')
    .replace(/<plugins>[\s\S]*?<\/plugins>/g, '');
  const out: DependencyRecord[] = [];
  for (const m of body.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const get = (tag: string) => new RegExp(`<${tag}>\\s*([^<]+?)\\s*</${tag}>`).exec(m[1] as string)?.[1];
    const group = get('groupId');
    const artifact = get('artifactId');
    const version = get('version');
    if (!group || !artifact || !version) continue;
    const v = resolve(version);
    if (v.includes('${')) continue;
    const s = get('scope');
    const name = `${group}:${artifact}`;
    out.push({
      ecosystem: 'Maven',
      name,
      version: v,
      manifestPath: path,
      direct: true,
      scope: s === 'test' ? 'test' : s === 'provided' || s === 'system' ? 'development' : 'runtime',
      purl: `pkg:maven/${group}/${artifact}@${v}`,
    });
  }
  return out;
}
