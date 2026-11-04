import { mkdir, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import {
  applyRedactions,
  normalizeRelPath,
  type RedactionSpan,
  type SecretScrubber,
  type SourceTree,
} from '@spinxsca/core';

export interface MaterializeOptions {
  source: SourceTree;
  /** Repository-relative paths of the snapshot. */
  paths: readonly string[];
  /** Destination directory (created; existing content is replaced). */
  dest: string;
  /** Data policy: files the model may not see are left out of the copy entirely. */
  allows?: (path: string) => boolean;
  /** Secret locations from the secret scanners (worktree). */
  redactions?: readonly RedactionSpan[];
  /** Known secret values and generic patterns. */
  scrubber?: SecretScrubber;
  /** Files larger than this are skipped (default 2 MB). */
  maxFileBytes?: number;
}

export interface MaterializedCopy {
  root: string;
  files: number;
  /** Files whose content changed because of redaction. */
  redactedFiles: string[];
  /** Files left out (data policy, binary, too large). */
  skipped: string[];
}

/**
 * Builds the analysis copy (ADR-043): only paths the data policy allows, every known secret span
 * masked, every known secret value and generic secret pattern scrubbed. The agent's sandboxed shell
 * mounts this copy read-only, never the repository itself.
 */
export async function materializeRedactedCopy(o: MaterializeOptions): Promise<MaterializedCopy> {
  const root = resolve(o.dest);
  await rm(root, { recursive: true, force: true });
  await mkdir(root, { recursive: true });
  const limit = o.maxFileBytes ?? 2 * 1024 * 1024;
  const out: MaterializedCopy = { root, files: 0, redactedFiles: [], skipped: [] };
  for (const raw of o.paths) {
    const path = normalizeRelPath(raw);
    if (!path || path.split('/').includes('..') || (o.allows && !o.allows(path))) {
      out.skipped.push(raw);
      continue;
    }
    const text = await o.source.readText(path);
    if (text === undefined || text.length > limit || text.includes('\0')) {
      out.skipped.push(path);
      continue;
    }
    let content = text;
    if (o.redactions?.some((r) => r.path === path)) {
      content = applyRedactions(content.split('\n'), 1, path, o.redactions).join('\n');
    }
    if (o.scrubber) content = o.scrubber.scrub(content);
    if (content !== text) out.redactedFiles.push(path);
    const target = join(root, path);
    if (!target.startsWith(root + sep)) {
      out.skipped.push(path);
      continue;
    }
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, content);
    out.files++;
  }
  return out;
}
