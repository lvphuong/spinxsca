import { existsSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CliError } from './ui';

/**
 * Locates the shipped Semgrep rule bundles: next to the bundled CLI (dist/rules/semgrep), in the
 * monorepo (rules/semgrep) during development, or at SPINXSCA_RULES_DIR.
 */
export function resolveRulesRoot(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    process.env.SPINXSCA_RULES_DIR,
    join(here, 'rules', 'semgrep'),
    resolve(here, '..', '..', '..', 'rules', 'semgrep'),
    resolve(here, '..', '..', 'rules', 'semgrep'),
  ].filter((c): c is string => Boolean(c));
  const found = candidates.find((c) => existsSync(join(c, 'spinxsca-core')));
  if (!found) throw new CliError(`cannot locate the spinxsca rule bundles (looked in ${candidates.join(', ')})`, 2);
  return found;
}

/** Locates the prompt bundle next to the bundled CLI, in the monorepo, or at SPINXSCA_PROMPTS_DIR. */
export function resolvePromptsDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    process.env.SPINXSCA_PROMPTS_DIR,
    join(here, 'prompts'),
    resolve(here, '..', '..', '..', 'prompts'),
    resolve(here, '..', '..', 'prompts'),
  ].filter((c): c is string => Boolean(c));
  const found = candidates.find((c) => existsSync(join(c, 'explain.md')));
  if (!found) throw new CliError(`cannot locate the prompt bundle (looked in ${candidates.join(', ')})`, 2);
  return found;
}

export function bundleSpecs(rulesRoot: string, extraDirs: readonly string[]): Array<{ id: string; dir: string }> {
  const specs = [{ id: 'spinxsca-core', dir: join(rulesRoot, 'spinxsca-core') }];
  for (const dir of extraDirs) {
    if (!existsSync(dir)) throw new CliError(`rule directory not found: ${dir}`, 2);
    specs.push({ id: `local-${basename(dir).replace(/[^a-zA-Z0-9_-]/g, '-')}`, dir });
  }
  return specs;
}
