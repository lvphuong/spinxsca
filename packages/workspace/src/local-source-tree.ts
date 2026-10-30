import { execFile } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { lstat, readdir, readFile } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { promisify } from 'node:util';
import { type GitInfo, normalizeRelPath, type SourceTree, sha256 } from '@spinxsca/core';
import { globToRegExp, RepositoryConfinement } from '@spinxsca/sandbox';
import type { SnapshotFile } from '@spinxsca/schemas';

const execFileAsync = promisify(execFile);

/** Directories skipped when the tree is not a git checkout (git checkouts use .gitignore). */
const DEFAULT_IGNORED_DIRS = new Set([
  '.git',
  '.spinxsca',
  'node_modules',
  '.venv',
  'venv',
  '__pycache__',
  '.next',
  '.turbo',
  'dist',
  'build',
  'target',
  'coverage',
]);
const ALWAYS_EXCLUDED = ['.spinxsca/**', '.git/**'];
const MAX_FILE_BYTES = 20 * 1024 * 1024;

export interface LocalSourceTreeOptions {
  /** Paths the agent and indexer may never read (in addition to scan excludes). */
  deny?: readonly string[];
}

/** SourceTree over a local directory, which may be the root or a subdirectory of a git checkout. */
export class LocalSourceTree implements SourceTree {
  readonly root: string;
  private readonly confinement: RepositoryConfinement;

  constructor(root: string, options: LocalSourceTreeOptions = {}) {
    this.root = realpathSync(root);
    this.confinement = new RepositoryConfinement(this.root, { deny: [...ALWAYS_EXCLUDED, ...(options.deny ?? [])] });
  }

  async listFiles(options: { exclude: readonly string[] }): Promise<SnapshotFile[]> {
    const excludes = [...ALWAYS_EXCLUDED, ...options.exclude].map(globToRegExp);
    const candidates = (await this.isGit()) ? await this.gitFiles() : await this.walk();
    const files: SnapshotFile[] = [];
    for (const path of candidates) {
      if (excludes.some((re) => re.test(path))) continue;
      const absolute = join(this.root, path);
      const info = await lstat(absolute).catch(() => undefined);
      if (!info?.isFile() || info.size > MAX_FILE_BYTES) continue;
      files.push({ path, digest: sha256(await readFile(absolute)), size: info.size });
    }
    return files.sort((a, b) => a.path.localeCompare(b.path));
  }

  async readText(relPath: string): Promise<string | undefined> {
    try {
      return await this.confinement.readText(relPath);
    } catch {
      return undefined;
    }
  }

  async gitInfo(): Promise<GitInfo | undefined> {
    if (!(await this.isGit())) return undefined;
    const commitSha = await this.git(['rev-parse', 'HEAD']).catch(() => undefined);
    if (!commitSha) return undefined;
    const treeSha = await this.git(['rev-parse', 'HEAD:./']).catch(() => undefined);
    const branch = await this.git(['rev-parse', '--abbrev-ref', 'HEAD']).catch(() => undefined);
    const status = await this.git(['status', '--porcelain', '--untracked-files=normal', '--', '.']);
    return {
      commitSha,
      ...(treeSha ? { treeSha } : {}),
      ...(branch && branch !== 'HEAD' ? { branch } : {}),
      dirty: status.length > 0,
    };
  }

  /** Changed paths (relative to this tree) between `baseRef` and the working tree, including untracked files. */
  async changedFiles(baseRef: string): Promise<string[]> {
    if (!(await this.isGit())) throw new Error('changed-file detection needs a git checkout');
    const { stdout } = await execFileAsync('git', ['diff', '--name-only', '-z', '--relative', baseRef, '--', '.'], {
      cwd: this.root,
      maxBuffer: 64 * 1024 * 1024,
    });
    const untracked = await execFileAsync('git', ['ls-files', '--others', '--exclude-standard', '-z'], {
      cwd: this.root,
    });
    const paths = [...stdout.split('\0'), ...untracked.stdout.split('\0')].filter(Boolean).map(normalizeRelPath);
    return [...new Set(paths)].sort();
  }

  private gitChecked: boolean | undefined;

  private async isGit(): Promise<boolean> {
    if (this.gitChecked === undefined) {
      this.gitChecked = (await this.git(['rev-parse', '--is-inside-work-tree']).catch(() => 'false')) === 'true';
    }
    return this.gitChecked;
  }

  private async gitFiles(): Promise<string[]> {
    const { stdout } = await execFileAsync('git', ['ls-files', '-co', '--exclude-standard', '-z'], {
      cwd: this.root,
      maxBuffer: 256 * 1024 * 1024,
    });
    return [...new Set(stdout.split('\0').filter(Boolean).map(normalizeRelPath))];
  }

  private async walk(): Promise<string[]> {
    const out: string[] = [];
    const visit = async (dir: string): Promise<void> => {
      for (const entry of await readdir(dir, { withFileTypes: true })) {
        if (entry.isSymbolicLink()) continue;
        const absolute = join(dir, entry.name);
        if (entry.isDirectory()) {
          if (!DEFAULT_IGNORED_DIRS.has(entry.name)) await visit(absolute);
        } else if (entry.isFile()) {
          out.push(relative(this.root, absolute).split(sep).join('/'));
        }
      }
    };
    await visit(this.root);
    return out;
  }

  private async git(args: string[]): Promise<string> {
    const { stdout } = await execFileAsync('git', args, { cwd: this.root });
    return stdout.trim();
  }
}
