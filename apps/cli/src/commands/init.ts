import { existsSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import pc from 'picocolors';
import { CONFIG_FILENAME, DEFAULT_CONFIG_YAML } from '../config';
import { EXIT } from '../ui';
import { infoCommand } from './info';

/** Writes a starter spinxsca.yaml in the current directory (never overwrites without --force) and runs preflight. */
export async function initCommand(options: { force?: boolean }): Promise<number> {
  const path = resolve(process.cwd(), CONFIG_FILENAME);
  if (existsSync(path) && !options.force) {
    process.stdout.write(`${pc.yellow('exists')} ${path} (use --force to overwrite)\n`);
  } else {
    writeFileSync(path, DEFAULT_CONFIG_YAML);
    process.stdout.write(`${pc.green('created')} ${path}\n`);
  }
  process.stdout.write('\n');
  const code = await infoCommand({});
  process.stdout.write(`\nNext: ${pc.bold('spinxsca scan <path>')}\n`);
  return code === EXIT.OK ? EXIT.OK : code;
}
