import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';
import { checkManifest, PersonaManifest } from './manifest';

export interface Persona {
  manifest: PersonaManifest;
  /** Prompt body with shared includes expanded (front matter removed). */
  prompt: string;
}

const FRONT_MATTER = /^---\n([\s\S]*?)\n---\n?/;

export function parseFrontMatter(text: string): { meta: unknown; body: string } {
  const match = FRONT_MATTER.exec(text);
  if (!match) return { meta: {}, body: text };
  return { meta: parse(match[1] as string) ?? {}, body: text.slice(match[0].length) };
}

/**
 * Loads persona prompts from `<promptsDir>/personas/*.md`. `@include(name.md)` lines are expanded from
 * `<promptsDir>/shared` and `<promptsDir>`; manifests that break the persona ceilings are rejected.
 */
export function loadPersonas(promptsDir: string): Map<string, Persona> {
  const dir = join(promptsDir, 'personas');
  if (!existsSync(dir)) throw new Error(`persona prompts not found at ${dir}`);
  const out = new Map<string, Persona>();
  const include = (name: string, depth: number): string => {
    if (depth > 5) throw new Error('prompt include depth exceeded');
    for (const base of [join(promptsDir, 'shared'), promptsDir, dir]) {
      const path = join(base, name);
      if (existsSync(path)) return expand(parseFrontMatter(readFileSync(path, 'utf8')).body, depth + 1);
    }
    throw new Error(`prompt include ${name} not found`);
  };
  const expand = (text: string, depth: number): string =>
    text.replace(/^@include\(([^)]+)\)\s*$/gm, (_m, name: string) => include(name.trim(), depth).trim());
  for (const file of readdirSync(dir)
    .filter((f) => f.endsWith('.md'))
    .sort()) {
    const { meta, body } = parseFrontMatter(readFileSync(join(dir, file), 'utf8'));
    const manifest = PersonaManifest.parse(meta);
    if (`${manifest.id}.md` !== file) throw new Error(`persona ${manifest.id} must live in ${manifest.id}.md`);
    const problems = checkManifest(manifest);
    if (problems.length) throw new Error(`invalid persona manifest:\n${problems.join('\n')}`);
    out.set(manifest.id, { manifest, prompt: expand(body, 0).trim() });
  }
  return out;
}
