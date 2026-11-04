import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ConfinementError, DockerSandboxRunner, globToRegExp, RepositoryConfinement } from '../src/index';

let dir: string;
let outside: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'spx-confine-'));
  outside = mkdtempSync(join(tmpdir(), 'spx-outside-'));
  mkdirSync(join(dir, 'src'));
  writeFileSync(join(dir, 'src/app.js'), 'console.log(1);\n');
  mkdirSync(join(dir, 'vendor'));
  writeFileSync(join(dir, 'vendor/lib.js'), 'x');
  writeFileSync(join(outside, 'secret.txt'), 'top secret');
  symlinkSync(join(outside, 'secret.txt'), join(dir, 'src/link.txt'));
  symlinkSync(outside, join(dir, 'linkdir'));
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
  rmSync(outside, { recursive: true, force: true });
});

describe('RepositoryConfinement', () => {
  const jail = () => new RepositoryConfinement(dir, { deny: ['vendor/**'] });

  it('reads files inside the root', async () => {
    expect(await jail().readText('src/app.js')).toBe('console.log(1);\n');
  });

  it('rejects traversal, absolute paths and the root itself', async () => {
    await expect(jail().readText('../etc/passwd')).rejects.toBeInstanceOf(ConfinementError);
    await expect(jail().readText('/etc/passwd')).rejects.toThrow('absolute paths');
    await expect(jail().readText('src/../..')).rejects.toBeInstanceOf(ConfinementError);
    await expect(jail().readText('.')).rejects.toBeInstanceOf(ConfinementError);
  });

  it('refuses symlinks to files and directories', async () => {
    await expect(jail().readText('src/link.txt')).rejects.toThrow('symbolic links');
    await expect(jail().readText('linkdir/secret.txt')).rejects.toThrow('symbolic links');
  });

  it('applies deny patterns', async () => {
    await expect(jail().readText('vendor/lib.js')).rejects.toThrow('excluded by policy');
  });

  it('does not leak host paths in errors', async () => {
    const error = await jail()
      .readText('../x')
      .catch((e: Error) => e);
    expect(String(error)).not.toContain(dir);
  });
});

describe('globToRegExp', () => {
  it('matches common patterns', () => {
    expect(globToRegExp('vendor/**').test('vendor/a/b.js')).toBe(true);
    expect(globToRegExp('**/*.test.ts').test('src/a.test.ts')).toBe(true);
    expect(globToRegExp('*.min.js').test('a.min.js')).toBe(true);
    expect(globToRegExp('*.min.js').test('dir/a.min.js')).toBe(false);
    expect(globToRegExp('fixtures').test('fixtures/x.json')).toBe(true);
  });
});

describe('DockerSandboxRunner', () => {
  it('always applies the hardening flags', () => {
    const args = new DockerSandboxRunner().buildRunArgs({
      name: 'n',
      image: `img@sha256:${'a'.repeat(64)}`,
      args: ['tool', '--version'],
      env: { B: '2', A: '1' },
      mounts: [{ hostPath: '/src', containerPath: '/src', readOnly: true }],
      workdir: '/src',
      profile: 'scan',
      resources: { cpus: 2, memoryMb: 1024, timeoutSec: 10 },
    });
    const joined = args.join(' ');
    for (const flag of [
      '--network none',
      '--cap-drop ALL',
      '--security-opt no-new-privileges',
      '--read-only',
      '--rm',
    ]) {
      expect(joined).toContain(flag);
    }
    expect(joined).toContain('type=bind,source=/src,target=/src,readonly');
    expect(joined).toContain('--env A=1 --env B=2');
    expect(args.slice(-3)).toEqual([`img@sha256:${'a'.repeat(64)}`, 'tool', '--version']);
    expect(joined).not.toMatch(/--user 0(:|\s)/);
  });

  it('refuses unpinned images and applies per-profile scratch space and runtime', () => {
    const runner = new DockerSandboxRunner({ runtime: 'runsc' });
    const spec = {
      name: 'n',
      image: 'node:22',
      args: [],
      env: {},
      mounts: [],
      workdir: '/',
      profile: 'analysis' as const,
      resources: { cpus: 1, memoryMb: 512, timeoutSec: 10 },
    };
    expect(() => runner.buildRunArgs(spec)).toThrow('unpinned image');
    const local = runner.buildRunArgs({ ...spec, image: `sha256:${'b'.repeat(64)}` }).join(' ');
    expect(local).toContain('--tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m');
    expect(local).toContain('--memory-swap 512m');
    expect(local).not.toContain('--runtime');
    expect(runner.hardeningArgs('validation').join(' ')).toContain('--runtime runsc');
    for (const profile of ['scan', 'analysis', 'validation', 'patch'] as const) {
      expect(runner.hardeningArgs(profile).join(' ')).toContain('--network none');
    }
  });

  const dockerAvailable = (() => {
    try {
      execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  })();

  it.runIf(dockerAvailable)('preflight reads back the effective hardened configuration', async () => {
    const image = 'semgrep/semgrep:1.182.1@sha256:451b3d875c00dac7ed5db5293e584a07de11449a409c10b3c2d2652f429630b6';
    const result = await new DockerSandboxRunner().preflight(image);
    const failed = result.checks.filter((c) => !c.ok && c.name !== 'scanner image');
    expect(failed).toEqual([]);
    expect(result.ok).toBe(true);
  });
});

describe('analysis copy and shell', () => {
  const secret = 'Zx9-very-secret-value-123';
  const files: Record<string, string> = {
    'src/app.js': `const key = "${secret}";\nconst aws = "AKIAABCDEFGHIJKLMNOP";\nmodule.exports = key;\n`,
    'src/config.js': 'const password = "hunter2hunter2";\n',
    'secrets/prod.env': 'TOKEN=abc',
    'README.md': 'hello',
  };
  const source = {
    root: '/',
    listFiles: async () => [],
    readText: async (p: string) => files[p],
    gitInfo: async () => undefined,
  };

  it('copies only allowed files with every known secret masked', async () => {
    const { createSecretScrubber } = await import('@spinxsca/core');
    const { materializeRedactedCopy } = await import('../src/index');
    const { mkdtempSync, readFileSync, readdirSync, rmSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dest = mkdtempSync(join(tmpdir(), 'spx-copy-'));
    try {
      const copy = await materializeRedactedCopy({
        source,
        paths: [...Object.keys(files), '../escape.txt'],
        dest: join(dest, 'src'),
        allows: (p) => !p.startsWith('secrets/'),
        redactions: [{ path: 'src/app.js', startLine: 1, endLine: 1, startColumn: 14, endColumn: 14 + secret.length }],
        scrubber: createSecretScrubber({ knownValues: [secret] }),
      });
      expect(copy.files).toBe(3);
      expect(copy.skipped).toEqual(expect.arrayContaining(['secrets/prod.env', '../escape.txt']));
      const all = (dir: string): string[] =>
        readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
          e.isDirectory() ? all(join(dir, e.name)) : [readFileSync(join(dir, e.name), 'utf8')],
        );
      const text = all(join(dest, 'src')).join('\n');
      for (const leaked of [secret, 'AKIAABCDEFGHIJKLMNOP', 'hunter2hunter2', 'TOKEN=abc'])
        expect(text).not.toContain(leaked);
      expect(copy.redactedFiles.sort()).toEqual(['src/app.js', 'src/config.js']);
    } finally {
      rmSync(dest, { recursive: true, force: true });
    }
  });

  const nodeImagePresent = (() => {
    try {
      execFileSync('docker', ['image', 'inspect', 'node:22-alpine'], { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  })();

  it.runIf(nodeImagePresent)(
    'the analysis shell has no network and a read-only source',
    async () => {
      const { runAnalysisShell, materializeRedactedCopy } = await import('../src/index');
      const { mkdtempSync, rmSync } = await import('node:fs');
      const { tmpdir } = await import('node:os');
      const { join } = await import('node:path');
      const dest = mkdtempSync(join(tmpdir(), 'spx-shell-'));
      try {
        await materializeRedactedCopy({ source, paths: ['src/app.js', 'README.md'], dest: join(dest, 'src') });
        const sandbox = new DockerSandboxRunner();
        const grep = await runAnalysisShell({
          sandbox,
          root: join(dest, 'src'),
          command: 'grep -rn module.exports . && cat README.md',
        });
        expect(grep.exitCode).toBe(0);
        expect(grep.stdout).toContain('src/app.js:3');
        const net = await runAnalysisShell({
          sandbox,
          root: join(dest, 'src'),
          command: 'wget -q -T 3 -O- http://1.1.1.1 || echo NO_NETWORK',
        });
        expect(net.stdout).toContain('NO_NETWORK');
        const write = await runAnalysisShell({
          sandbox,
          root: join(dest, 'src'),
          command: 'echo x > /src/README.md || echo READ_ONLY',
        });
        expect(write.stdout).toContain('READ_ONLY');
      } finally {
        rmSync(dest, { recursive: true, force: true });
      }
    },
    60_000,
  );
});
