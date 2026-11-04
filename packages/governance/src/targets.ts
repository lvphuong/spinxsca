import type { ActionTarget } from '@spinxsca/schemas';

/** `**` any depth, `*` within a segment, `?` one character; a bare directory also matches its contents. */
export function globToRegExp(pattern: string): RegExp {
  const p = pattern.replace(/^\.\//, '').replace(/\/+$/, '');
  let re = '';
  for (let i = 0; i < p.length; i++) {
    const ch = p[i] as string;
    if (ch === '*' && p[i + 1] === '*') {
      re += '.*';
      i++;
      if (p[i + 1] === '/') i++;
    } else if (ch === '*') re += '[^/]*';
    else if (ch === '?') re += '[^/]';
    else re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}(?:/.*)?$`);
}

export function matchesAny(path: string, globs: readonly string[]): boolean {
  return globs.some((g) => globToRegExp(g).test(path));
}

/**
 * Normalizes a repository-relative path. Returns undefined for anything that could escape the root:
 * absolute paths, drive letters, `..` segments, NUL bytes.
 */
export function safeRelPath(path: string): string | undefined {
  if (path.includes('\0') || /^[a-zA-Z]:/.test(path) || path.startsWith('/') || path.startsWith('\\')) return undefined;
  const parts = path.replace(/\\/g, '/').split('/');
  const out: string[] = [];
  for (const part of parts) {
    if (part === '' || part === '.') continue;
    if (part === '..') return undefined;
    out.push(part);
  }
  return out.length ? out.join('/') : undefined;
}

/** Relative part of a target inside the repository or a workspace (`<workspaceId>/<path>`). */
export function relPathOf(target: ActionTarget): string | undefined {
  if (target.kind === 'repo_path') return safeRelPath(target.value);
  if (target.kind === 'workspace_path') {
    const slash = target.value.indexOf('/');
    return slash < 0 ? '' : safeRelPath(target.value.slice(slash + 1));
  }
  return undefined;
}

export function workspaceIdOf(target: ActionTarget): string | undefined {
  if (target.kind !== 'workspace_path') return undefined;
  const slash = target.value.indexOf('/');
  return slash < 0 ? target.value : target.value.slice(0, slash);
}

/**
 * Governance surface of spinxsca inside any tree an agent can touch (L1 self-protection): local
 * state, operator configuration, prompts, playbooks and rules. Denied for every risk class.
 */
export const SELF_PROTECTED_GLOBS: readonly string[] = [
  '.spinxsca',
  '**/.spinxsca',
  'spinxsca.yaml',
  'spinxsca.yml',
  '**/spinxsca.yaml',
  '**/spinxsca.yml',
];

/** Governance tables an agent can never write, read through tools or name as a target. */
export const PROTECTED_STORES: readonly string[] = [
  'grants',
  'approvals',
  'dispositions',
  'baselines',
  'memory.promote',
  'audit',
  'policy',
];

/**
 * Files whose change alters how code is built, deployed or authenticated (L8). Writes to them in a
 * workspace are flagged `protectedTouched` and are never covered by standing rules or auto-allow.
 */
export const PROTECTED_TARGET_GLOBS: readonly string[] = [
  '.github',
  '.gitlab-ci.yml',
  '.circleci',
  'azure-pipelines.yml',
  'Jenkinsfile',
  '.git',
  '.husky',
  '.githooks',
  '**/Dockerfile',
  '**/Dockerfile.*',
  '**/docker-compose*.yml',
  '**/docker-compose*.yaml',
  '**/Makefile',
  'package.json',
  '**/package.json',
  '**/.npmrc',
  '**/setup.py',
  '**/setup.cfg',
  '**/pyproject.toml',
  '**/pom.xml',
  '**/build.gradle',
  '**/build.gradle.kts',
  '**/*auth*',
  '**/security',
  '**/.env',
  '**/.env.*',
];

export interface ProtectionOptions {
  /** Absolute host paths owned by the operator (config file, knowledge base, rule dirs, prompts). */
  protectedRoots?: readonly string[];
  /** `ai.autonomy.extra_protected` globs. */
  extraProtected?: readonly string[];
}

export function isSelfProtected(target: ActionTarget, options: ProtectionOptions = {}): boolean {
  if (target.kind === 'store') return PROTECTED_STORES.includes(target.value) || target.value.startsWith('memory.');
  if (target.kind === 'host_path') {
    return (options.protectedRoots ?? []).some(
      (root) => target.value === root || target.value.startsWith(root.endsWith('/') ? root : `${root}/`),
    );
  }
  const rel = relPathOf(target);
  return rel !== undefined && rel !== '' && matchesAny(rel, SELF_PROTECTED_GLOBS);
}

export function isProtectedTarget(target: ActionTarget, options: ProtectionOptions = {}): boolean {
  const rel = relPathOf(target);
  if (!rel) return false;
  return matchesAny(rel, PROTECTED_TARGET_GLOBS) || matchesAny(rel, options.extraProtected ?? []);
}

/** Canonical key of the primary target, used to bind grants to exactly what a human approved. */
export function targetKey(targets: readonly ActionTarget[]): string {
  const first = targets[0];
  return first ? `${first.kind}:${first.value}` : '*';
}
