import type { SnapshotFile, SourceSnapshot } from '@spinxsca/schemas';
import { sha256, sha256Hex } from './ids';
import type { ArtifactStore, Clock, SourceTree } from './ports';

export interface CapturedSnapshot {
  snapshot: SourceSnapshot;
  files: SnapshotFile[];
}

/**
 * Captures an immutable description of the source tree (ADR-002). A clean git checkout becomes a
 * GIT_COMMIT snapshot; anything with local changes becomes WORKSPACE and is never attributed to HEAD.
 */
export async function captureSnapshot(
  deps: { source: SourceTree; artifacts: ArtifactStore; clock: Clock },
  input: { repositoryId: string; exclude: readonly string[] },
): Promise<CapturedSnapshot> {
  const files = (await deps.source.listFiles({ exclude: input.exclude })).sort((a, b) => a.path.localeCompare(b.path));
  const contentManifestDigest = sha256(files.map((f) => `${f.path}\u0000${f.digest}`).join('\n'));
  const fileList = await deps.artifacts.put(JSON.stringify(files), 'application/json');
  const git = await deps.source.gitInfo();
  const kind = git && !git.dirty ? 'GIT_COMMIT' : 'WORKSPACE';
  const identity = [input.repositoryId, contentManifestDigest, kind, kind === 'GIT_COMMIT' ? git?.commitSha : ''].join(
    '|',
  );
  const snapshot: SourceSnapshot = {
    snapshotId: `snap_${sha256Hex(identity).slice(0, 24)}`,
    repositoryId: input.repositoryId,
    kind,
    ...(git?.commitSha && kind === 'GIT_COMMIT' ? { commitSha: git.commitSha } : {}),
    ...(git?.treeSha && kind === 'GIT_COMMIT' ? { treeSha: git.treeSha } : {}),
    ...(git?.branch ? { branchAtCapture: git.branch } : {}),
    contentManifestDigest,
    fileCount: files.length,
    fileListDigest: fileList.digest,
    capturedAt: deps.clock.now().toISOString(),
  };
  return { snapshot, files };
}
