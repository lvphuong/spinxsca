import type { AnalysisManifest, ChangeCause, RuleBundleRef, ScanMode, SourceSnapshot } from '@spinxsca/schemas';
import { digestOf } from './ids';
import type { KnowledgeBaseRef, ScannerAdapter } from './ports';
import { AI_POLICY_VERSION, ENGINE_VERSION } from './version';

export async function buildManifest(input: {
  scanId: string;
  snapshot: SourceSnapshot;
  scanners: readonly ScannerAdapter[];
  mode: ScanMode;
  exclude: readonly string[];
  baselineScanId: string | undefined;
  requestedAt: string;
  knowledgeBase?: KnowledgeBaseRef | null;
  aiPolicy?: AnalysisManifest['aiPolicy'];
  /** Overrides the branch recorded at capture (detached server checkouts). */
  branch?: string;
}): Promise<AnalysisManifest> {
  const scanners = input.scanners.map((s) => s.describe());
  const branch = input.branch ?? input.snapshot.branchAtCapture;
  const ruleBundles: RuleBundleRef[] = [];
  for (const scanner of input.scanners) ruleBundles.push(...(await scanner.ruleBundles()));
  const scannerEntries = scanners.map((s) => ({
    id: s.id,
    adapterVersion: s.adapterVersion,
    toolVersion: s.toolVersion,
    image: s.image,
  }));
  return {
    schemaVersion: 1,
    scanId: input.scanId,
    engineVersion: ENGINE_VERSION,
    source: {
      snapshotId: input.snapshot.snapshotId,
      contentManifestDigest: input.snapshot.contentManifestDigest,
      ...(input.snapshot.commitSha ? { commitSha: input.snapshot.commitSha } : {}),
      ...(branch ? { branch } : {}),
    },
    scannerBundle: { digest: digestOf(scannerEntries), scanners: scannerEntries },
    ruleBundles,
    knowledgeBase: input.knowledgeBase
      ? {
          snapshotId: input.knowledgeBase.snapshotId,
          digest: input.knowledgeBase.digest,
          ecosystems: input.knowledgeBase.ecosystems,
        }
      : null,
    aiPolicy: input.aiPolicy ?? { level: 'off', policyVersion: AI_POLICY_VERSION },
    scanMode: input.mode,
    ...(input.baselineScanId ? { baselineScanId: input.baselineScanId } : {}),
    scope: { exclude: [...input.exclude] },
    requestedAt: input.requestedAt,
  };
}

/** Explains why results may differ from the baseline by comparing the two frozen manifests. */
export function manifestChangeCauses(previous: AnalysisManifest | undefined, current: AnalysisManifest): ChangeCause[] {
  if (!previous) return ['FIRST_SCAN'];
  const causes: ChangeCause[] = [];
  if (previous.source.contentManifestDigest !== current.source.contentManifestDigest) causes.push('CODE_CHANGE');
  const prevRules = new Map(previous.ruleBundles.map((r) => [r.id, r.digest]));
  for (const bundle of current.ruleBundles) {
    const before = prevRules.get(bundle.id);
    if (before === undefined) causes.push('RULE_ADDED');
    else if (before !== bundle.digest) causes.push('RULE_UPDATED');
  }
  const prevScanners = new Map(previous.scannerBundle.scanners.map((s) => [s.id, `${s.image}|${s.adapterVersion}`]));
  const currentIds = new Set(current.scannerBundle.scanners.map((s) => s.id));
  for (const scanner of current.scannerBundle.scanners) {
    const before = prevScanners.get(scanner.id);
    if (before === undefined) causes.push('COVERAGE_CHANGE');
    else if (before !== `${scanner.image}|${scanner.adapterVersion}`) causes.push('SCANNER_UPGRADED');
  }
  if ([...prevScanners.keys()].some((id) => !currentIds.has(id))) causes.push('COVERAGE_CHANGE');
  const kbBefore = previous.knowledgeBase?.digest;
  const kbNow = current.knowledgeBase?.digest;
  if (kbBefore && kbNow && kbBefore !== kbNow) causes.push('ADVISORY_UPDATED');
  else if (Boolean(kbBefore) !== Boolean(kbNow)) causes.push('COVERAGE_CHANGE');
  if (digestOf(previous.scope) !== digestOf(current.scope)) causes.push('COVERAGE_CHANGE');
  return causes.length > 0 ? [...new Set(causes)] : ['UNKNOWN'];
}
