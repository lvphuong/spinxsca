/** Pulls every pinned scanner image (packages/scanners/src/images.json) by digest. */
import { execFileSync } from 'node:child_process';
import { imageRef, PINNED_IMAGES } from '../packages/scanners/src/index';

for (const [id, image] of Object.entries(PINNED_IMAGES)) {
  const ref = imageRef(image);
  console.log(`pulling ${id}: ${ref}`);
  execFileSync('docker', ['pull', '--quiet', ref], { stdio: 'inherit' });
}
