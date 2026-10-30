/**
 * Runs `semgrep --test` for every rule bundle under rules/semgrep inside the pinned, hardened
 * scanner container. Each rule must have a test target with `ruleid:` / `ok:` annotations.
 */
import { readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { DockerSandboxRunner } from '../packages/sandbox/src/index';
import { imageRef, PINNED_IMAGES } from '../packages/scanners/src/index';

const root = resolve(import.meta.dirname, '..', 'rules', 'semgrep');
const bundles = readdirSync(root).filter((name) => statSync(join(root, name)).isDirectory());
const runner = new DockerSandboxRunner();
let failed = 0;
for (const bundle of bundles) {
  const result = await runner.run({
    name: `spinxsca-rule-test-${bundle}-${process.pid}`,
    image: imageRef(PINNED_IMAGES.semgrep),
    args: ['semgrep', '--test', '--metrics=off', '--disable-version-check', '/rules'],
    env: { HOME: '/tmp', SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0' },
    mounts: [{ hostPath: join(root, bundle), containerPath: '/rules', readOnly: true }],
    workdir: '/rules',
    profile: 'scan',
    resources: { cpus: 2, memoryMb: 2048, timeoutSec: 600 },
  });
  const summary = result.stdout.split('\n').filter((l) => /tests? (passed|failed)|✓|✖|FAIL/i.test(l));
  console.log(`${bundle}: ${summary.join(' | ') || `exit ${result.exitCode}`}`);
  if (result.exitCode !== 0) {
    failed++;
    console.error(result.stdout.slice(-4000), result.stderr.slice(-2000));
  }
}
process.exit(failed === 0 ? 0 : 1);
