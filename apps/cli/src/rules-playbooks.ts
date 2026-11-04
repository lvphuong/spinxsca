import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CliError } from './ui';

/** Locates the security playbooks (playbooks/<id>/SKILL.md) next to the CLI, in the monorepo, or at SPINXSCA_PLAYBOOKS_DIR. */
export function resolvePlaybooksDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    process.env.SPINXSCA_PLAYBOOKS_DIR,
    join(here, 'playbooks'),
    resolve(here, '..', '..', '..', 'playbooks'),
    resolve(here, '..', '..', 'playbooks'),
  ].filter((c): c is string => Boolean(c));
  const found = candidates.find((c) => existsSync(join(c, 'sqli', 'SKILL.md')));
  if (!found) throw new CliError(`cannot locate the security playbooks (looked in ${candidates.join(', ')})`, 2);
  return found;
}
