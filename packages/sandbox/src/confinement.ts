import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';

export interface ConfinementOptions {
  /** Maximum bytes returned by a single read. */
  maxReadBytes?: number;
  /** Glob-like deny patterns (supports "**", "*" and directory prefixes). */
  deny?: readonly string[];
}

export class ConfinementError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfinementError';
  }
}

/**
 * Read-only jail over a source tree (ADR-023, modelled on shannon's confinement.ts): paths are
 * resolved against the real root, symlinks are refused, files are opened with O_NOFOLLOW and the
 * opened file is re-checked so a swap between check and open is detected. Errors never reveal
 * host paths outside the root.
 */
export class RepositoryConfinement {
  private realRoot: string | undefined;
  private readonly maxReadBytes: number;
  private readonly deny: RegExp[];

  constructor(
    readonly root: string,
    options: ConfinementOptions = {},
  ) {
    this.maxReadBytes = options.maxReadBytes ?? 2 * 1024 * 1024;
    this.deny = (options.deny ?? []).map(globToRegExp);
  }

  async resolve(relPath: string): Promise<{ absolute: string; relative: string }> {
    if (relPath.includes('\0')) throw new ConfinementError('invalid path');
    if (isAbsolute(relPath)) throw new ConfinementError('absolute paths are not allowed');
    const root = await this.getRealRoot();
    const absolute = resolve(root, relPath);
    const rel = relative(root, absolute);
    if (rel === '' || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
      throw new ConfinementError('path escapes the repository root');
    }
    const posix = rel.split(sep).join('/');
    if (this.deny.some((re) => re.test(posix))) throw new ConfinementError('path is excluded by policy');
    // Refuse symlinks in every component below the root.
    let current = root;
    for (const part of rel.split(sep)) {
      current = resolve(current, part);
      const info = await lstat(current).catch(() => undefined);
      if (!info) throw new ConfinementError('path does not exist');
      if (info.isSymbolicLink()) throw new ConfinementError('symbolic links are not followed');
    }
    return { absolute, relative: posix };
  }

  async readText(relPath: string): Promise<string> {
    const { absolute } = await this.resolve(relPath);
    const handle = await open(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)).catch(() => {
      throw new ConfinementError('file cannot be opened');
    });
    try {
      const info = await handle.stat();
      if (!info.isFile()) throw new ConfinementError('not a regular file');
      const after = await lstat(absolute);
      if (after.ino !== info.ino || after.dev !== info.dev) throw new ConfinementError('file changed while opening');
      const length = Math.min(info.size, this.maxReadBytes);
      const buffer = Buffer.alloc(length);
      await handle.read(buffer, 0, length, 0);
      return buffer.toString('utf8');
    } finally {
      await handle.close();
    }
  }

  private async getRealRoot(): Promise<string> {
    if (!this.realRoot) this.realRoot = await realpath(this.root);
    return this.realRoot;
  }
}

/** Minimal glob: "**" matches across directories, "*" within a segment, a bare prefix matches a directory. */
export function globToRegExp(pattern: string): RegExp {
  const trimmed = pattern.replace(/^\.\//, '').replace(/\/$/, '');
  let re = '';
  for (let i = 0; i < trimmed.length; i++) {
    const ch = trimmed[i] as string;
    if (ch === '*' && trimmed[i + 1] === '*') {
      re += '.*';
      i++;
      if (trimmed[i + 1] === '/') i++;
    } else if (ch === '*') re += '[^/]*';
    else if (ch === '?') re += '[^/]';
    else re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}(?:/.*)?$`);
}
