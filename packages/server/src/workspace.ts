import { execFile } from 'node:child_process';
import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { promisify } from 'node:util';
import type { ProjectEntry } from './registry';

const execFileAsync = promisify(execFile);

/**
 * Git is run without hooks, prompts, or exotic transports: the repository URL is operator input,
 * but the repository content is untrusted (ADR-025).
 */
const GIT_SAFE = [
  '-c',
  'core.hooksPath=/dev/null',
  '-c',
  'protocol.ext.allow=never',
  '-c',
  'protocol.fd.allow=never',
  '-c',
  'advice.detachedHead=false',
];
const GIT_ENV = { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_PROTOCOL_FROM_USER: '0', GIT_CONFIG_NOSYSTEM: '1' };

async function git(args: string[], cwd?: string): Promise<string> {
  try {
    const { stdout } = await execFileAsync('git', [...GIT_SAFE, ...args], {
      cwd,
      env: GIT_ENV,
      maxBuffer: 64 * 1024 * 1024,
      timeout: 15 * 60_000,
    });
    return stdout.trim();
  } catch (err) {
    const e = err as { stderr?: string; message: string };
    throw new Error(
      `git ${args.find((a, i) => !a.startsWith('-') && args[i - 1] !== '-c' && args[i - 1] !== '--git-dir') ?? ''} failed: ${(e.stderr ?? e.message).trim().split('\n').slice(-3).join(' ')}`,
    );
  }
}

export interface Checkout {
  dir: string;
  commit?: string;
  dispose(): Promise<void>;
}

/** Per-project directories: state (SQLite + artifacts), a bare mirror, and per-job worktrees. */
export class ProjectWorkspace {
  constructor(readonly dataDir: string) {}

  paths(projectId: string): { root: string; state: string; repo: string; work: string } {
    const root = join(this.dataDir, 'projects', projectId);
    return { root, state: join(root, 'state'), repo: join(root, 'repo.git'), work: join(root, 'work') };
  }

  /** Clones (first time) and fetches branch heads plus any extra refs (pull/merge request heads). */
  async fetch(project: ProjectEntry, extraRefs: Array<{ remote: string; local: string }> = []): Promise<void> {
    if (project.source.kind !== 'git') return;
    const { repo } = this.paths(project.projectId);
    // A repository on the server's own disk is an explicit operator choice; only then is the file
    // transport allowed (it stays blocked for anything a remote repository could reference).
    const local = isAbsolute(project.source.url) || project.source.url.startsWith('file://');
    const transport = local ? ['-c', 'protocol.file.allow=always'] : [];
    if (!existsSync(join(repo, 'HEAD'))) {
      mkdirSync(join(repo, '..'), { recursive: true });
      await git([...transport, 'clone', '--bare', '--quiet', '--', project.source.url, repo]);
    }
    const refspecs = ['+refs/heads/*:refs/heads/*', ...extraRefs.map((r) => `+${r.remote}:${r.local}`)];
    await git([...transport, '--git-dir', repo, 'fetch', '--quiet', '--prune', '--no-tags', 'origin', ...refspecs]);
  }

  async resolve(project: ProjectEntry, ref: string): Promise<string> {
    if (project.source.kind !== 'git') throw new Error('only git projects have refs');
    return git(['--git-dir', this.paths(project.projectId).repo, 'rev-parse', '--verify', `${ref}^{commit}`]);
  }

  /** A detached worktree at `commit` for one job; local projects are scanned in place. */
  async checkout(project: ProjectEntry, commit: string | undefined, jobId: string): Promise<Checkout> {
    if (project.source.kind === 'local') {
      return { dir: project.source.path, dispose: async () => {} };
    }
    if (!commit) throw new Error('a commit is required to check out a git project');
    const { repo, work } = this.paths(project.projectId);
    const dir = join(work, jobId);
    mkdirSync(work, { recursive: true });
    if (existsSync(dir)) await this.remove(repo, dir);
    await git(['--git-dir', repo, 'worktree', 'add', '--detach', '--force', '--quiet', dir, commit]);
    return { dir, commit, dispose: () => this.remove(repo, dir) };
  }

  private async remove(repo: string, dir: string): Promise<void> {
    try {
      await git(['--git-dir', repo, 'worktree', 'remove', '--force', dir]);
    } catch {
      rmSync(dir, { recursive: true, force: true });
      await git(['--git-dir', repo, 'worktree', 'prune']).catch(() => {});
    }
  }
}
