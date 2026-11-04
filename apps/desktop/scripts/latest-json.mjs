// Builds the updater manifest (latest.json) from signed bundles (*.sig) collected from the release
// matrix: node latest-json.mjs <version> <base download URL> <dir with bundles>.
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';

const [version, baseUrl, dir] = process.argv.slice(2);
if (!version || !baseUrl || !dir) throw new Error('usage: latest-json.mjs <version> <baseUrl> <dir>');
const files = [];
const walk = (d) => {
  for (const name of readdirSync(d)) {
    const p = join(d, name);
    if (statSync(p).isDirectory()) walk(p);
    else files.push(p);
  }
};
walk(dir);
const platformOf = (name) =>
  /aarch64.*\.app\.tar\.gz$/.test(name) ? 'darwin-aarch64'
  : /x64.*\.app\.tar\.gz$|x86_64.*\.app\.tar\.gz$/.test(name) ? 'darwin-x86_64'
  : /\.AppImage$/.test(name) ? 'linux-x86_64'
  : /-setup\.exe$/.test(name) ? 'windows-x86_64'
  : undefined;
const platforms = {};
for (const sig of files.filter((f) => f.endsWith('.sig'))) {
  const artifact = sig.slice(0, -4);
  const platform = platformOf(basename(artifact));
  if (!platform) continue;
  platforms[platform] = { signature: readFileSync(sig, 'utf8').trim(), url: `${baseUrl.replace(/\/+$/, '')}/${basename(artifact)}` };
}
if (Object.keys(platforms).length === 0) throw new Error('no signed bundles found (is TAURI_SIGNING_PRIVATE_KEY set?)');
writeFileSync('latest.json', `${JSON.stringify({ version, pub_date: new Date().toISOString(), platforms }, null, 2)}\n`);
console.log(`latest.json: ${Object.keys(platforms).join(', ')}`);
