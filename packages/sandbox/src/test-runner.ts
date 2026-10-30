import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { ContainerRunResult, SandboxRunner } from '@spinxsca/core';

export const NODE_IMAGE = 'node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914';
export const PYTHON_IMAGE =
  'python:3.12-alpine@sha256:5789aa194f757888f41fa3d48e14b6feaa1b57c0af0b56fcb1372d6474d3bff0';

export interface TestRunOutcome {
  status: 'passed' | 'failed' | 'skipped' | 'not_available';
  output: string;
  command?: string;
}

/**
 * Runs the project's own tests inside the `patch` sandbox profile (docs/architecture/03 section 11):
 * no network, read-only root filesystem, the workspace copy mounted read-write. Dependencies must
 * already be installed in the workspace (node_modules, .venv); nothing is downloaded.
 */
export async function runProjectTests(
  sandbox: SandboxRunner,
  workspace: string,
  signal?: AbortSignal,
): Promise<TestRunOutcome> {
  const pkgPath = join(workspace, 'package.json');
  if (existsSync(pkgPath)) {
    const pkg = JSON.parse(await import('node:fs/promises').then((fs) => fs.readFile(pkgPath, 'utf8'))) as {
      scripts?: Record<string, string>;
    };
    const script = pkg.scripts?.test;
    if (!script || /no test specified/.test(script))
      return { status: 'not_available', output: 'package.json has no test script' };
    if (!existsSync(join(workspace, 'node_modules')))
      return {
        status: 'skipped',
        output: 'node_modules not installed in the workspace; install dependencies before `spinxsca fix` to run tests',
      };
    const result = await run(
      sandbox,
      NODE_IMAGE,
      ['npm', 'test', '--silent'],
      workspace,
      { CI: 'true', NODE_ENV: 'test', npm_config_update_notifier: 'false' },
      signal,
    );
    return { status: result.exitCode === 0 ? 'passed' : 'failed', output: tail(result), command: 'npm test' };
  }
  if (
    existsSync(join(workspace, 'pytest.ini')) ||
    existsSync(join(workspace, 'pyproject.toml')) ||
    existsSync(join(workspace, 'tests'))
  ) {
    const venv = ['.venv', 'venv'].find((v) => existsSync(join(workspace, v, 'bin', 'python')));
    if (!venv)
      return {
        status: 'skipped',
        output: 'no .venv in the workspace; create one with pytest installed before `spinxsca fix` to run tests',
      };
    const result = await run(
      sandbox,
      PYTHON_IMAGE,
      [`/work/${venv}/bin/python`, '-m', 'pytest', '-q', '-x'],
      workspace,
      { PYTHONDONTWRITEBYTECODE: '1' },
      signal,
    );
    return { status: result.exitCode === 0 ? 'passed' : 'failed', output: tail(result), command: 'pytest' };
  }
  return { status: 'not_available', output: 'no supported test runner detected (npm test or pytest)' };
}

async function run(
  sandbox: SandboxRunner,
  image: string,
  args: string[],
  workspace: string,
  env: Record<string, string>,
  signal?: AbortSignal,
): Promise<ContainerRunResult> {
  return sandbox.run(
    {
      name: `spinxsca-tests-${process.pid}-${Date.now()}`,
      image,
      args,
      env: { HOME: '/tmp', ...env },
      mounts: [{ hostPath: workspace, containerPath: '/work', readOnly: false }],
      workdir: '/work',
      profile: 'patch',
      resources: { cpus: 2, memoryMb: 2048, pidsLimit: 1024, timeoutSec: 600 },
    },
    signal,
  );
}

function tail(result: ContainerRunResult): string {
  const text = `${result.stdout}\n${result.stderr}`.trim();
  const lines = text.split('\n');
  return (
    (lines.length > 80 ? ['...', ...lines.slice(-80)] : lines).join('\n') + (result.timedOut ? '\n[timed out]' : '')
  );
}
