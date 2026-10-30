import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { sha256 } from '@spinxsca/core';
import type { Digest } from '@spinxsca/schemas';

export interface PromptBundle {
  dir: string;
  digest: Digest;
  render(
    name: 'explain' | 'ask' | 'planner' | 'investigator' | 'auditor' | 'remediation',
    vars?: Record<string, string>,
  ): string;
}

/**
 * Loads the prompt bundle (docs/architecture/03 section 6). The digest covers every file so a prompt
 * change is visible in the Analysis Manifest of later scans.
 */
export function loadPromptBundle(dir: string): PromptBundle {
  if (!existsSync(join(dir, 'explain.md'))) throw new Error(`prompt bundle not found at ${dir}`);
  const files = listFiles(dir).sort();
  const contents = new Map(files.map((f) => [relative(dir, f).split(sep).join('/'), readFileSync(f, 'utf8')]));
  const digest = sha256([...contents.entries()].map(([name, text]) => `${name}\u0000${text}`).join('\n'));
  const expand = (name: string, depth = 0): string => {
    if (depth > 5) throw new Error('prompt include depth exceeded');
    const text = contents.get(name);
    if (text === undefined) throw new Error(`prompt ${name} not found in bundle`);
    return text.replace(/^@include\(([^)]+)\)\s*$/gm, (_m, include: string) =>
      expand(include.trim(), depth + 1).trim(),
    );
  };
  return {
    dir,
    digest,
    render(name, vars = {}) {
      return expand(`${name}.md`)
        .replace(/\{\{(\w+)\}\}/g, (m, key: string) => vars[key] ?? m)
        .trim();
    },
  };
}

function listFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return listFiles(path);
    return name.endsWith('.md') && name !== 'README.md' ? [path] : [];
  });
}
