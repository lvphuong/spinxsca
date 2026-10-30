import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { ScannerRunContext } from '@spinxsca/core';
import type { SnapshotFile } from '@spinxsca/schemas';

export const HOME_ENV = { HOME: '/tmp', XDG_CONFIG_HOME: '/tmp', XDG_CACHE_HOME: '/tmp' };

export function containerName(prefix: string, taskId: string): string {
  return `spinxsca-${prefix}-${taskId.replace(/[^a-zA-Z0-9_.-]/g, '-')}`;
}

export async function snapshotFiles(ctx: ScannerRunContext): Promise<SnapshotFile[]> {
  return JSON.parse(await ctx.artifacts.getText(ctx.snapshot.fileListDigest)) as SnapshotFile[];
}

export async function readOutput(dir: string, name: string): Promise<string | undefined> {
  return readFile(join(dir, name), 'utf8').catch(() => undefined);
}

/** Strips the container mount prefix from a reported path. */
export function relativeToSrc(path: string): string {
  return path.replace(/^\/src\/?/, '').replace(/^(\.\/)+/, '');
}

export function tail(text: string, lines = 15): string {
  return text.trim().split('\n').slice(-lines).join('\n');
}

export function extensionOf(path: string): string {
  return path.slice(path.lastIndexOf('.') + 1).toLowerCase();
}
