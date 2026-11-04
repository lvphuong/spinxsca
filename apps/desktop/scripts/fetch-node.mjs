// Downloads the official Node.js runtime for a target platform (ADR-048) and verifies it against the
// release's SHASUMS256.txt. The sidecar ships this binary, never the build machine's node (a Homebrew
// or nvm node links against local libraries and is not portable).
//   node fetch-node.mjs [--version v24.x.y] [--platform darwin|win32|linux] [--arch arm64|x64]
// Prints the path of the cached binary. Archives are cached in apps/desktop/.cache/node.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const defaultCache = resolve(here, '..', '.cache', 'node');
const mirror = (process.env.SPINXSCA_NODE_MIRROR ?? 'https://nodejs.org/dist').replace(/\/+$/, '');

const OS = { darwin: 'darwin', win32: 'win', linux: 'linux' };

async function download(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`GET ${url}: HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

/**
 * Returns `{ binary, license, version, sha256 }` for the requested runtime, downloading and
 * verifying the archive the first time.
 */
export async function fetchNode({
  version = process.version,
  platform = process.platform,
  arch = process.arch,
  cacheDir = defaultCache,
} = {}) {
  const os = OS[platform];
  if (!os) throw new Error(`unsupported platform ${platform}`);
  if (!['arm64', 'x64'].includes(arch)) throw new Error(`unsupported arch ${arch}`);
  const v = version.startsWith('v') ? version : `v${version}`;
  const base = `node-${v}-${os}-${arch}`;
  const archive = `${base}${platform === 'win32' ? '.zip' : '.tar.gz'}`;
  const dir = join(cacheDir, base);
  const inner = platform === 'win32' ? ['node.exe'] : ['bin', 'node'];
  const binary = join(dir, ...inner);
  const license = join(dir, 'LICENSE');
  const stamp = join(dir, '.sha256');
  if (existsSync(binary) && existsSync(stamp)) {
    return { binary, license, version: v, sha256: readFileSync(stamp, 'utf8').trim() };
  }

  const sums = (await download(`${mirror}/${v}/SHASUMS256.txt`)).toString('utf8');
  const expected = sums
    .split('\n')
    .map((l) => l.trim().split(/\s+/))
    .find(([, name]) => name === archive)?.[0];
  if (!expected) throw new Error(`${archive} is not listed in ${mirror}/${v}/SHASUMS256.txt`);
  const data = await download(`${mirror}/${v}/${archive}`);
  const actual = createHash('sha256').update(data).digest('hex');
  if (actual !== expected) throw new Error(`checksum mismatch for ${archive}: expected ${expected}, got ${actual}`);

  mkdirSync(cacheDir, { recursive: true });
  const tmp = join(cacheDir, `${base}.partial`);
  rmSync(tmp, { recursive: true, force: true });
  mkdirSync(tmp, { recursive: true });
  const file = join(tmp, archive);
  writeFileSync(file, data);
  // bsdtar (macOS, Windows 10+) reads zip as well as tar.gz; GNU tar on Linux only sees tar.gz here.
  const members = [[base, ...inner].join('/'), `${base}/LICENSE`];
  // On a Windows host use the system bsdtar: a GNU tar from Git for Windows earlier on PATH cannot read zip.
  const tar =
    process.platform === 'win32' ? join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
  execFileSync(tar, [platform === 'win32' ? '-xf' : '-xzf', file, '-C', tmp, ...members], { stdio: 'inherit' });
  rmSync(file);
  writeFileSync(join(tmp, base, '.sha256'), `${actual}\n`);
  rmSync(dir, { recursive: true, force: true });
  renameSync(join(tmp, base), dir);
  rmSync(tmp, { recursive: true, force: true });
  return { binary, license, version: v, sha256: actual };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const opt = (name) => {
    const i = args.indexOf(`--${name}`);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const result = await fetchNode({
    ...(opt('version') ? { version: opt('version') } : {}),
    ...(opt('platform') ? { platform: opt('platform') } : {}),
    ...(opt('arch') ? { arch: opt('arch') } : {}),
  });
  console.log(result.binary);
}
