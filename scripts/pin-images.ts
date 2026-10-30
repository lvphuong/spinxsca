/**
 * Re-resolves the multi-architecture digest of every scanner image in
 * packages/scanners/src/images.json. Bump a tag with `pnpm images:pin semgrep=1.183.0`.
 * Review the diff: a digest change alters every subsequent Analysis Manifest (ADR-021).
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const file = resolve(import.meta.dirname, '..', 'packages', 'scanners', 'src', 'images.json');
const images = JSON.parse(readFileSync(file, 'utf8')) as Record<
  string,
  { repository: string; tag: string; digest: string; toolVersion: string }
>;
const bumps = new Map(
  process.argv
    .slice(2)
    .map((arg) => arg.split('='))
    .filter((parts): parts is [string, string] => parts.length === 2),
);

for (const [name, image] of Object.entries(images)) {
  const tag = bumps.get(name) ?? image.tag;
  const output = execFileSync('docker', ['buildx', 'imagetools', 'inspect', `${image.repository}:${tag}`], {
    encoding: 'utf8',
  });
  const digest = /^Digest:\s+(sha256:[0-9a-f]{64})/m.exec(output)?.[1];
  if (!digest) throw new Error(`could not resolve digest for ${image.repository}:${tag}`);
  if (digest !== image.digest || tag !== image.tag) {
    console.log(`${name}: ${image.repository}:${image.tag}@${image.digest} -> ${tag}@${digest}`);
  } else {
    console.log(`${name}: unchanged (${tag}@${digest})`);
  }
  images[name] = { ...image, tag, digest, toolVersion: bumps.has(name) ? tag : image.toolVersion };
}
writeFileSync(file, `${JSON.stringify(images, null, 2)}\n`);
