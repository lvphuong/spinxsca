import { randomBytes } from 'node:crypto';
import type { ContainerRunResult, SandboxRunner } from '@spinxsca/core';
import { PROFILES } from './profiles';
import { NODE_IMAGE } from './test-runner';

/** Default analysis toolbox: the pinned Node image (busybox sh, grep, find, sed, awk, node). */
export const DEFAULT_TOOLBOX_IMAGE = NODE_IMAGE;

export interface AnalysisShellOptions {
  sandbox: SandboxRunner;
  /** Materialized, redacted copy mounted read-only at /src. */
  root: string;
  command: string;
  image?: string;
  timeoutSec?: number;
  signal?: AbortSignal;
}

const MAX_OUTPUT = 30_000;

/**
 * Runs one shell command for the agent in the `analysis` profile (ADR-043): no network, read-only
 * root filesystem and source, small noexec /tmp, one CPU, short timeout. The command runs through
 * `sh -c`; nothing it does can reach the repository or the host.
 */
export async function runAnalysisShell(o: AnalysisShellOptions): Promise<ContainerRunResult> {
  const limits = PROFILES.analysis.resources;
  const result = await o.sandbox.run(
    {
      name: `spinxsca-shell-${randomBytes(6).toString('hex')}`,
      image: o.image ?? DEFAULT_TOOLBOX_IMAGE,
      args: ['sh', '-c', o.command],
      env: { HOME: '/tmp', LANG: 'C.UTF-8', PAGER: 'cat' },
      mounts: [{ hostPath: o.root, containerPath: '/src', readOnly: true }],
      workdir: '/src',
      profile: 'analysis',
      resources: {
        cpus: limits.cpus,
        memoryMb: limits.memoryMb,
        pidsLimit: limits.pidsLimit,
        timeoutSec: Math.min(o.timeoutSec ?? limits.timeoutSec, limits.timeoutSec),
      },
    },
    o.signal,
  );
  return { ...result, stdout: clip(result.stdout), stderr: clip(result.stderr) };
}

function clip(text: string): string {
  return text.length <= MAX_OUTPUT
    ? text
    : `${text.slice(0, MAX_OUTPUT)}\n[truncated ${text.length - MAX_OUTPUT} characters]`;
}
