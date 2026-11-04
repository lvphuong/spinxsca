// Stages the local spinxsca service into src-tauri/sidecar for `tauri build` (ADR-048): the Node
// runtime running this script, and the bundled CLI with its production dependencies
// (better-sqlite3 native module, tree-sitter WASM grammars). Run after `pnpm build`.
import { execFileSync } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..', '..');
const out = resolve(here, '..', 'src-tauri', 'sidecar');

if (!existsSync(join(repo, 'apps', 'cli', 'dist', 'index.mjs'))) {
  throw new Error('apps/cli/dist is missing: run `pnpm build` first');
}
for (const entry of readdirSync(out)) if (entry !== 'README.md') rmSync(join(out, entry), { recursive: true, force: true });

// pnpm deploy copies the package's published files (dist) and installs only production dependencies.
execFileSync('pnpm', ['--filter', '@spinxsca/cli', 'deploy', '--prod', '--legacy', join(out, 'cli')], { cwd: repo, stdio: 'inherit' });
const cliDist = join(out, 'cli', 'dist');
copyFileSync(join(out, 'cli', 'dist', 'index.mjs'), join(out, 'cli', 'index.mjs'));
// index.mjs resolves rules, prompts and playbooks next to itself.
for (const dir of ['rules', 'prompts', 'playbooks']) {
  execFileSync(process.platform === 'win32' ? 'xcopy' : 'cp', process.platform === 'win32' ? ['/E', '/I', '/Q', join(cliDist, dir), join(out, 'cli', dir)] : ['-R', join(cliDist, dir), join(out, 'cli', dir)]);
}

const nodeDir = join(out, 'node', process.platform === 'win32' ? '' : 'bin');
mkdirSync(nodeDir, { recursive: true });
const nodeTarget = join(nodeDir, process.platform === 'win32' ? 'node.exe' : 'node');
copyFileSync(process.execPath, nodeTarget);
if (process.platform !== 'win32') chmodSync(nodeTarget, 0o755);
console.log(`staged sidecar in ${out} (node ${process.version}, ${process.platform}-${process.arch})`);
