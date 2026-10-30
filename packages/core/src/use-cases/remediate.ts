import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, sep } from 'node:path';
import type { AgentRunRecord, PatchProposal, PatchResult } from '@spinxsca/schemas';
import { unifiedDiff } from '../diff';
import { errorMessage, SpinxscaError } from '../errors';
import { newId } from '../ids';
import type { ExplainSubject, FindingExplainer, ScanRepository, SourceTree } from '../ports';
import { PRESENT_STATES } from '../reconcile';
import { loadSubject } from './explain';
import { runScan, type ScanDeps } from './run-scan';

/** Remediation role (implemented by @spinxsca/agent). */
export interface Remediator {
  readonly info: FindingExplainer['info'];
  propose(
    subject: ExplainSubject,
    source: SourceTree,
    signal?: AbortSignal,
  ): Promise<{ proposal?: PatchProposal; run: AgentRunRecord }>;
}

/** A scratch state directory whose scans can target different source directories (original vs patched copy). */
export interface Workspace {
  deps(sourceDir: string): ScanDeps;
  close(): void;
}

export interface RemediationDeps {
  scan: ScanDeps;
  remediator: Remediator;
  openWorkspace: (stateDir: string) => Promise<Workspace>;
  runTests: (
    workspace: string,
    signal?: AbortSignal,
  ) => Promise<{ status: 'passed' | 'failed' | 'skipped' | 'not_available'; output: string }>;
  /** Directory where workspaces and patches are kept (.spinxsca/patches). */
  patchesDir: string;
}

const NON_CODE_SCANNERS = new Set(['osv-scanner', 'gitleaks', 'trivy']);

/**
 * `spinxsca fix` (docs/architecture/03 section 10, ADR-026): the model proposes line edits; the host
 * applies them to a workspace copy, re-scans original and patched copies with the same code scanners
 * so identities line up, runs the project's tests in the sandbox, and only a patch whose finding is
 * RESOLVED with passing tests is `verified`. Nothing is written to the repository.
 */
export async function fixFinding(deps: RemediationDeps, findingId: string, signal?: AbortSignal): Promise<PatchResult> {
  const subject = await loadSubject(
    { repo: deps.scan.repo, artifacts: deps.scan.artifacts, source: deps.scan.source },
    findingId,
  );
  const createdAt = new Date().toISOString();
  const patchId = newId('patch');
  const base = { patchId, findingId, scanId: subject.scan.scanId, createdAt };
  const notRun: PatchResult['verification'] = { rescan: 'NOT_RUN', newFindings: [], tests: 'not_available' };
  const proposed = await deps.remediator.propose(subject, deps.scan.source, signal);
  const runId = proposed.run.agentRunId;
  await deps.scan.repo.saveAgentRun(proposed.run);
  if (!proposed.proposal) {
    return {
      ...base,
      status: 'failed',
      reason: `remediation ${proposed.run.status.toLowerCase()}${proposed.run.error ? `: ${proposed.run.error}` : ''}`,
      files: [],
      runId,
      verification: notRun,
    };
  }
  const proposal = proposed.proposal;

  // Copies live outside the repository (the state directory is usually inside it); only the diff,
  // the patched files and the result are kept under .spinxsca/patches/<id>.
  const root = join(deps.patchesDir, patchId);
  mkdirSync(root, { recursive: true });
  const scratch = mkdtempSync(join(tmpdir(), 'spinxsca-fix-'));
  const workspace = join(scratch, 'workspace');
  const original = join(scratch, 'original');
  for (const dir of [workspace, original]) {
    mkdirSync(dir, { recursive: true });
    cpSync(deps.scan.source.root, dir, {
      recursive: true,
      filter: (p) =>
        !p.split(sep).includes('.spinxsca') && !p.split(sep).includes('.git') && !p.split(sep).includes('node_modules'),
    });
  }
  if (existsSync(join(deps.scan.source.root, 'node_modules'))) {
    // Project tests need installed dependencies; copy them when present (never installed by spinxsca).
    try {
      cpSync(join(deps.scan.source.root, 'node_modules'), join(workspace, 'node_modules'), {
        recursive: true,
        dereference: false,
      });
    } catch {
      /* dependencies are optional for verification */
    }
  }
  const originals = new Map<string, string>();
  try {
    applyEdits(workspace, proposal, subject.snapshotPaths, originals);
  } catch (err) {
    return { ...base, status: 'failed', reason: errorMessage(err), proposal, files: [], runId, verification: notRun };
  }
  const files = [...originals.keys()].sort();
  const diff = files
    .map((f) => unifiedDiff(originals.get(f) as string, readFileSync(join(workspace, f), 'utf8'), f))
    .filter(Boolean)
    .join('\n');
  if (!diff) {
    rmSync(scratch, { recursive: true, force: true });
    rmSync(root, { recursive: true, force: true });
    return { ...base, status: 'no_change', reason: proposal.summary, proposal, files, runId, verification: notRun };
  }
  writeFileSync(join(root, 'patch.diff'), `${diff}\n`);
  for (const file of files) {
    mkdirSync(dirname(join(root, 'files', file)), { recursive: true });
    writeFileSync(join(root, 'files', file), readFileSync(join(workspace, file)));
  }

  // Re-scan: original copy first (so the finding gets an identity in the scratch state), then the patched copy.
  const ws = await deps.openWorkspace(join(scratch, 'state'));
  let rescan: PatchResult['verification']['rescan'] = 'INCONCLUSIVE';
  let rescanScanId: string | undefined;
  const newFindings: string[] = [];
  try {
    const scanners = subject.scan.manifest.scannerBundle.scanners
      .map((s) => s.id)
      .filter((id) => !NON_CODE_SCANNERS.has(id));
    const request = {
      projectName: 'fix-verify',
      mode: 'FULL' as const,
      exclude: subject.scan.manifest.scope.exclude,
      reuseCache: false,
      scanners,
      ...(signal ? { signal } : {}),
    };
    const before = await runScan(ws.deps(original), { ...request, baseline: { kind: 'none' } });
    const target = await findingAt(ws.deps(original).repo, before.scan.scanId, subject);
    const after = await runScan(ws.deps(workspace), {
      ...request,
      baseline: { kind: 'scan', scanId: before.scan.scanId },
    });
    rescanScanId = after.scan.scanId;
    for (const a of after.assessments) if (a.reconciliationState === 'NEW') newFindings.push(a.findingId);
    if (target) {
      const state = after.assessments.find((a) => a.findingId === target)?.reconciliationState;
      rescan =
        state === 'RESOLVED'
          ? 'RESOLVED'
          : state === undefined || state === 'NOT_REEVALUATED'
            ? 'INCONCLUSIVE'
            : PRESENT_STATES.has(state)
              ? 'STILL_PRESENT'
              : 'INCONCLUSIVE';
    }
  } finally {
    ws.close();
    rmSync(original, { recursive: true, force: true });
  }
  const tests = await deps.runTests(workspace, signal);
  rmSync(scratch, { recursive: true, force: true });
  const verification: PatchResult['verification'] = {
    rescan,
    ...(rescanScanId ? { rescanScanId } : {}),
    newFindings,
    tests: tests.status,
    testOutput: tests.output.slice(-4000),
  };
  let status: PatchResult['status'];
  let reason: string;
  if (rescan === 'STILL_PRESENT') [status, reason] = ['failed', 'the finding is still reported after the patch'];
  else if (rescan !== 'RESOLVED')
    [status, reason] = [
      'blocked',
      'the re-scan could not prove the finding is gone (no coverage or no matching finding in the copy)',
    ];
  else if (newFindings.length)
    [status, reason] = ['failed', `the patch introduces new findings: ${newFindings.join(', ')}`];
  else if (tests.status === 'failed') [status, reason] = ['failed', 'project tests fail with the patch applied'];
  else if (tests.status === 'passed')
    [status, reason] = ['verified', 'finding resolved in re-scan and project tests pass'];
  else
    [status, reason] = [
      'rescan_passed',
      `finding resolved in re-scan; tests ${tests.status.replace('_', ' ')}: ${tests.output.split('\n')[0]}`,
    ];
  const result: PatchResult = { ...base, status, reason, proposal, files, diff, runId, verification };
  writeFileSync(join(root, 'result.json'), JSON.stringify(result, null, 2));
  return result;
}

/** Applies a re-scan-verified patch to the repository working tree (developer-approved step). */
export function applyPatchToRepository(
  source: SourceTree,
  patchesDir: string,
  patchId: string,
): { files: string[]; result: PatchResult } {
  const resultPath = join(patchesDir, patchId, 'result.json');
  if (!existsSync(resultPath)) throw new SpinxscaError(`patch ${patchId} not found`, 'NOT_FOUND');
  const result = JSON.parse(readFileSync(resultPath, 'utf8')) as PatchResult;
  if (result.status !== 'verified' && result.status !== 'rescan_passed') {
    throw new SpinxscaError(`patch ${patchId} is ${result.status}; only verified patches can be applied`, 'INVALID');
  }
  const filesDir = join(patchesDir, patchId, 'files');
  for (const file of result.files) {
    const patched = join(filesDir, file);
    if (!existsSync(patched)) throw new SpinxscaError(`patched file ${file} is missing from ${filesDir}`, 'NOT_FOUND');
    writeFileSync(join(source.root, file), readFileSync(patched));
  }
  return { files: result.files, result };
}

export type VerifyFixStatus = 'fixed' | 'still_vulnerable' | 'inconclusive';

/**
 * `spinxsca verify-fix` (ADR-026): a targeted re-scan of the finding's file against the scan that
 * last reported it. Read-only with respect to the repository; accepts only coverage-backed evidence.
 */
export async function verifyFix(
  deps: ScanDeps,
  findingId: string,
  signal?: AbortSignal,
): Promise<{ status: VerifyFixStatus; scanId: string; reason: string }> {
  const finding = await deps.repo.getFinding(findingId);
  if (!finding) throw new SpinxscaError(`finding ${findingId} not found`, 'NOT_FOUND');
  const occurrence = (await deps.repo.occurrencesForFinding(findingId)).at(-1);
  if (!occurrence) throw new SpinxscaError(`finding ${findingId} has no recorded occurrence`, 'NOT_FOUND');
  const reported = await deps.repo.getScan(occurrence.scanId);
  if (!reported) throw new SpinxscaError(`scan ${occurrence.scanId} not found`, 'NOT_FOUND');
  const scanners = reported.manifest.scannerBundle.scanners.map((s) => s.id).filter((id) => !NON_CODE_SCANNERS.has(id));
  const outcome = await runScan(deps, {
    projectName: finding.projectId,
    mode: 'TARGETED',
    paths: [occurrence.anchor.path],
    exclude: reported.manifest.scope.exclude,
    baseline: { kind: 'scan', scanId: reported.scanId },
    reuseCache: false,
    scanners,
    ...(signal ? { signal } : {}),
  });
  const state = outcome.assessments.find((a) => a.findingId === findingId)?.reconciliationState;
  if (state === 'RESOLVED')
    return {
      status: 'fixed',
      scanId: outcome.scan.scanId,
      reason: 'not reported by a complete targeted re-scan of the file',
    };
  if (state && PRESENT_STATES.has(state))
    return {
      status: 'still_vulnerable',
      scanId: outcome.scan.scanId,
      reason: `still reported (${state.toLowerCase()})`,
    };
  return {
    status: 'inconclusive',
    scanId: outcome.scan.scanId,
    reason: state
      ? `state ${state.toLowerCase()}: coverage does not prove absence`
      : 'the finding was not evaluated by the re-scan',
  };
}

async function findingAt(repo: ScanRepository, scanId: string, subject: ExplainSubject): Promise<string | undefined> {
  const loc = subject.occurrence.locations[0];
  if (!loc) return undefined;
  const occurrences = await repo.listOccurrences(scanId);
  const exact = occurrences.find(
    (o) =>
      o.locations[0]?.path === loc.path &&
      o.locations[0]?.startLine === loc.startLine &&
      o.ruleIds.some((r) => subject.occurrence.ruleIds.includes(r)),
  );
  return (
    exact ?? occurrences.find((o) => o.locations[0]?.path === loc.path && o.locations[0]?.startLine === loc.startLine)
  )?.findingId;
}

function applyEdits(
  workspace: string,
  proposal: PatchProposal,
  allowed: readonly string[],
  originals: Map<string, string>,
): void {
  const allowedSet = new Set(allowed);
  const byFile = new Map<string, PatchProposal['edits']>();
  for (const edit of proposal.edits) {
    if (!allowedSet.has(edit.path))
      throw new SpinxscaError(`edit targets ${edit.path}, which is not a file of the snapshot`, 'INVALID');
    if (edit.endLine < edit.startLine)
      throw new SpinxscaError(`edit on ${edit.path} has endLine before startLine`, 'INVALID');
    byFile.set(edit.path, [...(byFile.get(edit.path) ?? []), edit]);
  }
  for (const [path, edits] of byFile) {
    const file = join(workspace, path);
    const text = readFileSync(file, 'utf8');
    originals.set(path, text);
    const lines = text.split('\n');
    const sorted = [...edits].sort((a, b) => b.startLine - a.startLine);
    for (let i = 1; i < sorted.length; i++) {
      const later = sorted[i - 1] as PatchProposal['edits'][number];
      const earlier = sorted[i] as PatchProposal['edits'][number];
      if (earlier.endLine >= later.startLine) throw new SpinxscaError(`overlapping edits in ${path}`, 'INVALID');
    }
    for (const edit of sorted) {
      if (edit.endLine > lines.length)
        throw new SpinxscaError(
          `edit on ${path} ends at line ${edit.endLine} but the file has ${lines.length} lines`,
          'INVALID',
        );
      const replacement = edit.replacement === '' ? [] : edit.replacement.replace(/\n$/, '').split('\n');
      lines.splice(edit.startLine - 1, edit.endLine - edit.startLine + 1, ...replacement);
    }
    writeFileSync(file, lines.join('\n'));
  }
}

export { applyEdits as applyPatchEdits };
