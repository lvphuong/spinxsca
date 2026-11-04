// Stages the local spinxsca service into src-tauri/sidecar for `tauri build` (ADR-048):
//   sidecar/node/bin/node (node/node.exe on Windows)  the official Node.js runtime of the target
//   sidecar/cli/dist/index.mjs                         the bundled CLI (with rules, prompts, playbooks)
//   sidecar/cli/node_modules                           production dependencies, flat (no symlinks)
//   sidecar/manifest.json                              what was staged, for the release notes
// Run after `pnpm build`:  node stage-sidecar.mjs [--target <rust triple>] [--node-version v24.x.y]
import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fetchNode } from './fetch-node.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..', '..');
const out = resolve(here, '..', 'src-tauri', 'sidecar');

const TARGETS = {
  'aarch64-apple-darwin': { platform: 'darwin', arch: 'arm64' },
  'x86_64-apple-darwin': { platform: 'darwin', arch: 'x64' },
  'x86_64-pc-windows-msvc': { platform: 'win32', arch: 'x64' },
  'x86_64-unknown-linux-gnu': { platform: 'linux', arch: 'x64' },
  'aarch64-unknown-linux-gnu': { platform: 'linux', arch: 'arm64' },
};
const hostTarget = () =>
  Object.keys(TARGETS).find((t) => TARGETS[t].platform === process.platform && TARGETS[t].arch === process.arch);

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const target = opt('target') ?? hostTarget();
if (!target || !TARGETS[target]) {
  throw new Error(`unsupported target ${target ?? `${process.platform}-${process.arch}`}; one of ${Object.keys(TARGETS).join(', ')}`);
}
const { platform, arch } = TARGETS[target];
const nodeVersion = opt('node-version') ?? process.version;

function run(cmd, argv, options = {}) {
  // pnpm is a .cmd shim on Windows, which needs a shell; quote what has spaces.
  const win = process.platform === 'win32';
  const quoted = win ? argv.map((a) => (/[\s"]/.test(a) ? `"${a.replaceAll('"', '\\"')}"` : a)) : argv;
  execFileSync(cmd, quoted, { cwd: repo, stdio: 'inherit', shell: win, ...options });
}

if (!existsSync(join(repo, 'apps', 'cli', 'dist', 'index.mjs'))) {
  throw new Error('apps/cli/dist is missing: run `pnpm build` first');
}
for (const dir of ['rules', 'prompts', 'playbooks']) {
  if (!existsSync(join(repo, 'apps', 'cli', 'dist', dir))) throw new Error(`apps/cli/dist/${dir} is missing: rebuild the CLI`);
}
mkdirSync(out, { recursive: true });
for (const entry of readdirSync(out)) if (entry !== 'README.md') rmSync(join(out, entry), { recursive: true, force: true });

// 1. The CLI and its production dependencies, resolved from the lockfile for the target platform.
// dist/ stays intact: index.mjs imports its sibling chunks and finds rules/prompts/playbooks next to itself.
const cliDir = join(out, 'cli');
// `deploy` records its own settings (production, hoisted, target cpu/os) in the workspace state file,
// after which every `pnpm run` in the repo wants to reinstall; put the developer's state back.
const stateFile = join(repo, 'node_modules', '.pnpm-workspace-state-v1.json');
const savedState = existsSync(stateFile) ? readFileSync(stateFile) : undefined;
try {
  run('pnpm', [
    '--filter',
    '@spinxsca/cli',
    'deploy',
    '--prod',
    '--legacy',
    '--ignore-scripts',
    '--config.node-linker=hoisted',
    `--os=${platform}`,
    `--cpu=${arch}`,
    cliDir,
  ]);
} finally {
  if (savedState) writeFileSync(stateFile, savedState);
}

// 2. Prune what the target never loads: other platforms' binaries, native sources, bin shims.
const nm = join(cliDir, 'node_modules');
const rm = (...p) => rmSync(join(nm, ...p), { recursive: true, force: true });
rm('.bin');
const bridge = join(nm, '@temporalio', 'core-bridge');
if (existsSync(join(bridge, 'releases'))) {
  if (!existsSync(join(bridge, 'releases', target, 'index.node'))) throw new Error(`@temporalio/core-bridge has no build for ${target}`);
  for (const r of readdirSync(join(bridge, 'releases'))) if (r !== target) rm('@temporalio', 'core-bridge', 'releases', r);
  for (const p of ['sdk-core', 'src', 'bridge-macros', 'Cargo.toml', 'Cargo.lock']) rm('@temporalio', 'core-bridge', p);
}
const sqlitePrebuilds = join(nm, 'better-sqlite3', 'prebuilds');
if (existsSync(sqlitePrebuilds)) {
  const keep = platform === 'linux' ? [`linux-${arch}.node`, `linuxmusl-${arch}.node`] : [`${platform}-${arch}.node`];
  if (!keep.some((k) => existsSync(join(sqlitePrebuilds, k)))) throw new Error(`better-sqlite3 has no prebuild for ${platform}-${arch}`);
  for (const f of readdirSync(sqlitePrebuilds)) if (!keep.includes(f)) rm('better-sqlite3', 'prebuilds', f);
  for (const p of ['deps', 'src', 'binding.gyp']) rm('better-sqlite3', p);
}
// Grammars load as WASM (web-tree-sitter); their native bindings and C sources are dead weight.
const pruneGrammars = (dir) => {
  for (const name of readdirSync(dir)) {
    if (!name.startsWith('tree-sitter-')) continue;
    for (const p of ['prebuilds', 'src', 'bindings', 'binding.gyp', 'build']) {
      rmSync(join(dir, name, p), { recursive: true, force: true });
    }
    if (existsSync(join(dir, name, 'node_modules'))) pruneGrammars(join(dir, name, 'node_modules'));
  }
};
pruneGrammars(nm);

// Symlinks do not survive bundling and break code signing of the app; the hoisted layout has none.
const links = [];
const walk = (d) => {
  for (const name of readdirSync(d)) {
    const p = join(d, name);
    const st = lstatSync(p);
    if (st.isSymbolicLink()) links.push(p);
    else if (st.isDirectory()) walk(p);
  }
};
walk(cliDir);
if (links.length) throw new Error(`the staged CLI contains symlinks:\n${links.slice(0, 10).join('\n')}`);

// 3. The official Node.js runtime of the target, checksum-verified.
const node = await fetchNode({ version: nodeVersion, platform, arch });
const nodeDir = join(out, 'node', ...(platform === 'win32' ? [] : ['bin']));
mkdirSync(nodeDir, { recursive: true });
const nodeTarget = join(nodeDir, platform === 'win32' ? 'node.exe' : 'node');
copyFileSync(node.binary, nodeTarget);
copyFileSync(node.license, join(out, 'node', 'LICENSE'));
if (platform !== 'win32') chmodSync(nodeTarget, 0o755);

// 4. Smoke test when the target runs here: the runtime loads the native modules and the CLI starts.
if (target === hostTarget()) {
  const probe = `require(${JSON.stringify(join(nm, 'better-sqlite3'))})(':memory:').close();`;
  execFileSync(nodeTarget, ['-e', probe], { stdio: 'inherit' });
  execFileSync(nodeTarget, [join(cliDir, 'dist', 'index.mjs'), '--version'], { stdio: 'inherit' });
}

const desktopPkg = JSON.parse(readFileSync(join(repo, 'apps', 'desktop', 'package.json'), 'utf8'));
writeFileSync(
  join(out, 'manifest.json'),
  `${JSON.stringify({ target, node: { version: node.version, sha256: node.sha256 }, app: desktopPkg.version, stagedAt: new Date().toISOString() }, null, 2)}\n`,
);
console.log(`staged sidecar for ${target} in ${out} (node ${node.version})`);
