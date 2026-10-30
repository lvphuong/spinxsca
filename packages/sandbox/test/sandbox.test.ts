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
      image: 'img@sha256:abc',
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
    expect(args.slice(-3)).toEqual(['img@sha256:abc', 'tool', '--version']);
    expect(joined).not.toMatch(/--user 0(:|\s)/);
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
