import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { LocalSourceTree } from '../src/index';

const dirs: string[] = [];
function tree(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'spx-tree-'));
  dirs.push(dir);
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(join(dir, path, '..'), { recursive: true });
    writeFileSync(join(dir, path), content);
  }
  return dir;
}
const git = (cwd: string, ...args: string[]) =>
  execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args], {
    cwd,
    stdio: 'pipe',
  });

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('LocalSourceTree', () => {
  it('walks a plain directory, skipping ignored directories and symlinks', async () => {
    const dir = tree({ 'src/a.js': 'a', 'node_modules/x/index.js': 'x', '.spinxsca/state.db': 's', 'b.py': 'b' });
    symlinkSync(join(dir, 'b.py'), join(dir, 'link.py'));
    const source = new LocalSourceTree(dir);
    const files = await source.listFiles({ exclude: [] });
    expect(files.map((f) => f.path)).toEqual(['b.py', 'src/a.js']);
    expect(files[0]?.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(await source.gitInfo()).toBeUndefined();
  });

  it('applies exclude globs', async () => {
    const dir = tree({ 'src/a.js': 'a', 'src/a.test.js': 't', 'fixtures/f.json': '{}' });
    const files = await new LocalSourceTree(dir).listFiles({ exclude: ['**/*.test.js', 'fixtures'] });
    expect(files.map((f) => f.path)).toEqual(['src/a.js']);
  });

  it('uses git for file listing and detects dirty subdirectories', async () => {
    const dir = tree({ 'app/src/a.js': 'a', 'app/ignored.log': 'l', '.gitignore': '*.log\n', 'other/b.js': 'b' });
    git(dir, 'init', '-q', '-b', 'main');
    git(dir, 'add', '.');
    git(dir, 'commit', '-q', '-m', 'init');
    const source = new LocalSourceTree(join(dir, 'app'));
    expect((await source.listFiles({ exclude: [] })).map((f) => f.path)).toEqual(['src/a.js']);
    const clean = await source.gitInfo();
    expect(clean?.dirty).toBe(false);
    expect(clean?.commitSha).toMatch(/^[0-9a-f]{40}$/);
    expect(clean?.branch).toBe('main');
    writeFileSync(join(dir, 'other/b.js'), 'changed elsewhere');
    expect((await source.gitInfo())?.dirty).toBe(false);
    writeFileSync(join(dir, 'app/src/new.js'), 'n');
    expect((await source.gitInfo())?.dirty).toBe(true);
  });

  it('lists files changed since a ref, relative to a subdirectory', async () => {
    const dir = tree({ 'app/src/a.js': 'a', 'app/src/b.js': 'b', 'other/c.js': 'c' });
    git(dir, 'init', '-q', '-b', 'main');
    git(dir, 'add', '.');
    git(dir, 'commit', '-q', '-m', 'init');
    writeFileSync(join(dir, 'app/src/b.js'), 'changed');
    writeFileSync(join(dir, 'app/src/new.js'), 'new');
    writeFileSync(join(dir, 'other/c.js'), 'changed too');
    expect(await new LocalSourceTree(join(dir, 'app')).changedFiles('HEAD')).toEqual(['src/b.js', 'src/new.js']);
  });

  it('reads text through the confinement and hides failures', async () => {
    const dir = tree({ 'src/a.js': 'hello' });
    const source = new LocalSourceTree(dir);
    expect(await source.readText('src/a.js')).toBe('hello');
    expect(await source.readText('../../etc/passwd')).toBeUndefined();
  });
});
