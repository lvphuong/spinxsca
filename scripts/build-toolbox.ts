/**
 * Builds the analysis toolbox image (deploy/toolbox/Dockerfile) and prints the content-addressed
 * reference to pin in operator configuration (`ai.autonomy.toolbox_image`). The image id is a
 * sha256 of the image configuration, so the reference cannot drift like a tag.
 */
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const tag = 'spinxsca-toolbox:local';
execFileSync('docker', ['build', '-t', tag, join(root, 'deploy/toolbox')], { stdio: 'inherit' });
const id = execFileSync('docker', ['image', 'inspect', '--format', '{{.Id}}', tag]).toString().trim();
if (!/^sha256:[0-9a-f]{64}$/.test(id)) throw new Error(`unexpected image id ${id}`);
console.log(`\nPinned toolbox image: ${id}\n\nAdd to spinxsca.yaml:\n\nai:\n  autonomy:\n    toolbox_image: "${id}"\n`);
