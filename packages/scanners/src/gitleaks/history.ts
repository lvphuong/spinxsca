import { existsSync, statSync } from 'node:fs';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { HistorySecretsPort, SandboxRunner } from '@spinxsca/core';
import { imageRef, PINNED_IMAGES, type PinnedImage } from '../images';
import { HOME_ENV, readOutput, tail } from '../shared';
import { GITLEAKS_CONFIG } from './adapter';

interface GitleaksHistoryFinding {
  Commit?: string;
  File?: string;
  StartLine?: number;
  RuleID?: string;
  Fingerprint?: string;
}

/**
 * Secrets in the git history (ADR-043): `gitleaks git --redact` over every ref, in the scan sandbox
 * with the repository mounted read-only. Only commit, path, line, rule and fingerprint leave the
 * container; secret values are redacted by gitleaks itself. Shallow clones are DEGRADED.
 */
export function gitHistorySecrets(o: {
  sandbox: SandboxRunner;
  repoRoot: string;
  workDir: string;
  image?: PinnedImage;
}): HistorySecretsPort {
  return {
    async scan(signal) {
      const gitPath = join(o.repoRoot, '.git');
      if (!existsSync(gitPath)) return { outcome: 'NOT_RUN', reason: 'not a git repository', secrets: [] };
      if (!statSync(gitPath).isDirectory()) {
        return {
          outcome: 'NOT_RUN',
          reason: 'git worktree or submodule: history lives outside the repository',
          secrets: [],
        };
      }
      const shallow = existsSync(join(gitPath, 'shallow'));
      const outDir = join(o.workDir, 'out');
      const cfgDir = join(o.workDir, 'cfg');
      await mkdir(outDir, { recursive: true });
      await mkdir(cfgDir, { recursive: true });
      await writeFile(join(cfgDir, 'gitleaks.toml'), GITLEAKS_CONFIG);
      try {
        const image = o.image ?? PINNED_IMAGES.gitleaks;
        const result = await o.sandbox.run(
          {
            name: `spinxsca-gitleaks-history-${Date.now()}`,
            image: imageRef(image),
            args: [
              'git',
              '/src',
              '--log-opts=--all',
              '--config',
              '/cfg/gitleaks.toml',
              '--redact',
              '--report-format',
              'json',
              '--report-path',
              '/out/history.json',
              '--exit-code',
              '0',
              '--no-banner',
              '--log-level',
              'error',
            ],
            env: {
              ...HOME_ENV,
              // The mounted repository is owned by the host user; let git read it.
              GIT_CONFIG_COUNT: '1',
              GIT_CONFIG_KEY_0: 'safe.directory',
              GIT_CONFIG_VALUE_0: '*',
            },
            mounts: [
              { hostPath: o.repoRoot, containerPath: '/src', readOnly: true },
              { hostPath: cfgDir, containerPath: '/cfg', readOnly: true },
              { hostPath: outDir, containerPath: '/out', readOnly: false },
            ],
            workdir: '/tmp',
            profile: 'scan',
            resources: { cpus: 2, memoryMb: 1024, timeoutSec: 900 },
          },
          signal,
        );
        const raw = await readOutput(outDir, 'history.json');
        if (raw === undefined) {
          return {
            outcome: 'NOT_RUN',
            reason: `gitleaks produced no output (exit ${result.exitCode}): ${tail(result.stderr, 3)}`,
            secrets: [],
          };
        }
        const secrets = (JSON.parse(raw) as GitleaksHistoryFinding[]).map((f) => ({
          commit: (f.Commit ?? '').slice(0, 40),
          path: f.File ?? '',
          line: f.StartLine ?? 1,
          ruleId: f.RuleID ?? 'unknown',
          fingerprint: f.Fingerprint ?? '',
        }));
        if (result.timedOut) return { outcome: 'DEGRADED', reason: 'history scan timed out', secrets };
        if (shallow) return { outcome: 'DEGRADED', reason: 'shallow clone: older history was not scanned', secrets };
        return { outcome: 'RAN', secrets };
      } finally {
        await rm(o.workDir, { recursive: true, force: true });
      }
    },
  };
}
