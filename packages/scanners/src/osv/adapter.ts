import { mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type {
  CandidateDraft,
  SandboxRunner,
  ScannerAdapter,
  ScannerResult,
  ScannerRunContext,
  SourceTree,
} from '@spinxsca/core';
import { ENGINE_VERSION, sha256Hex } from '@spinxsca/core';
import {
  type Confidence,
  type Coverage,
  normalizeCwe,
  type RuleBundleRef,
  type ScannerCapability,
  type Severity,
  type SnapshotFile,
} from '@spinxsca/schemas';
import { imageRef, PINNED_IMAGES, type PinnedImage } from '../images';
import { containerName, HOME_ENV, readOutput, relativeToSrc, snapshotFiles, tail } from '../shared';
import { locatePackage } from './locate';

export const OSV_ADAPTER_VERSION = '0.1.0';

/** What the adapter needs from the knowledge base (implemented by @spinxsca/kb). */
export interface OsvDatabaseProvider {
  /** Directory containing osv-scalibr/<ecosystem>/all.zip built from exactly the snapshot's records. */
  materialize(snapshotId: string, ecosystems: readonly string[]): Promise<string>;
  covers(snapshotId: string, ecosystem: string, name: string): Promise<boolean>;
}

const MANIFESTS: Array<[RegExp, string]> = [
  [/(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock)$/, 'npm'],
  [/(^|\/)(requirements[^/]*\.txt|poetry\.lock|Pipfile\.lock|uv\.lock|pdm\.lock|pylock\.toml)$/, 'PyPI'],
  [/(^|\/)(pom\.xml|gradle\.lockfile|buildscript-gradle\.lockfile)$/, 'Maven'],
  [/(^|\/)go\.mod$/, 'Go'],
  [/(^|\/)Cargo\.lock$/, 'crates.io'],
  [/(^|\/)Gemfile\.lock$/, 'RubyGems'],
  [/(^|\/)composer\.lock$/, 'Packagist'],
  [/(^|\/)packages\.lock\.json$/, 'NuGet'],
  [/(^|\/)pubspec\.lock$/, 'Pub'],
  [/(^|\/)mix\.lock$/, 'Hex'],
];

export function manifestEcosystem(path: string): string | undefined {
  return MANIFESTS.find(([re]) => re.test(path))?.[1];
}

interface OsvVuln {
  id: string;
  summary?: string;
  aliases?: string[];
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ type: string; events: Array<Record<string, string>> }>;
  }>;
  database_specific?: { severity?: string; cwe_ids?: string[] };
}

interface OsvOutput {
  results?: Array<{
    source: { path: string; type: string };
    packages?: Array<{
      package: { name: string; version: string; ecosystem: string; purl?: string };
      vulnerabilities?: OsvVuln[];
      groups?: Array<{ ids: string[]; aliases?: string[]; max_severity?: string }>;
    }>;
  }>;
}

/**
 * OSV-Scanner adapter (docs/architecture/04 section 5). Version matching is delegated to the OSV
 * reference implementation; the vulnerability data comes only from the knowledge base snapshot frozen
 * in the manifest, so results are reproducible and the container needs no network.
 */
export class OsvScannerAdapter implements ScannerAdapter {
  private readonly image: PinnedImage;

  constructor(private readonly options: { database: OsvDatabaseProvider; image?: PinnedImage }) {
    this.image = options.image ?? PINNED_IMAGES['osv-scanner'];
  }

  describe(): ScannerCapability {
    return {
      id: 'osv-scanner',
      adapterVersion: OSV_ADAPTER_VERSION,
      toolVersion: this.image.toolVersion,
      image: imageRef(this.image),
      capabilities: ['SCA'],
      languages: ['dependencies'],
      scanModes: ['FULL'],
      outputs: ['NATIVE_JSON'],
      requiresNetwork: false,
      requiresBuild: false,
      resources: { cpus: 2, memoryMb: 2048, timeoutSec: 900 },
    };
  }

  async ruleBundles(): Promise<RuleBundleRef[]> {
    return [];
  }

  applies(files: readonly SnapshotFile[]): boolean {
    return files.some((f) => manifestEcosystem(f.path) !== undefined);
  }

  /**
   * Dependency inventory only (no vulnerability data needed), used to scope a package-level
   * knowledge base sync to what a project actually uses.
   */
  async inventory(input: {
    source: SourceTree;
    sandbox: SandboxRunner;
    workDir: string;
    signal?: AbortSignal;
  }): Promise<Array<{ ecosystem: string; name: string; version: string; path: string }>> {
    const outDir = join(input.workDir, 'out');
    const cfgDir = join(input.workDir, 'cfg');
    await mkdir(outDir, { recursive: true });
    await mkdir(cfgDir, { recursive: true });
    await writeFile(join(cfgDir, 'osv-scanner.toml'), '');
    try {
      const capability = this.describe();
      await input.sandbox.run(
        {
          name: containerName('osv-inventory', `${process.pid}-${Date.now()}`),
          image: capability.image,
          args: [
            'scan',
            'source',
            '--offline',
            '--format',
            'json',
            '--all-packages',
            '--config',
            '/cfg/osv-scanner.toml',
            '--output-file',
            '/out/osv.json',
            '-r',
            '/src',
          ],
          env: { ...HOME_ENV, OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: '/tmp/osvdb' },
          mounts: [
            { hostPath: input.source.root, containerPath: '/src', readOnly: true },
            { hostPath: cfgDir, containerPath: '/cfg', readOnly: true },
            { hostPath: outDir, containerPath: '/out', readOnly: false },
          ],
          workdir: '/tmp',
          profile: 'scan',
          resources: capability.resources,
        },
        input.signal,
      );
      const raw = await readOutput(outDir, 'osv.json');
      if (raw === undefined) return [];
      const output = JSON.parse(raw) as OsvOutput;
      return (output.results ?? []).flatMap((r) =>
        (r.packages ?? []).map((p) => ({
          ecosystem: p.package.ecosystem,
          name: p.package.name,
          version: p.package.version,
          path: relativeToSrc(r.source.path),
        })),
      );
    } finally {
      await rm(input.workDir, { recursive: true, force: true });
    }
  }

  async run(ctx: ScannerRunContext): Promise<ScannerResult> {
    const files = await snapshotFiles(ctx);
    const manifests = files.filter((f) => manifestEcosystem(f.path));
    const ecosystems = [...new Set(manifests.map((f) => manifestEcosystem(f.path) as string))].sort();
    const kb = ctx.knowledgeBase;
    if (!kb) {
      return {
        drafts: [],
        rawArtifacts: {},
        coverage: emptyCoverage(
          files.length,
          'the vulnerability knowledge base is empty; run `spinxsca kb sync` first',
        ),
      };
    }
    const dbDir = await this.options.database.materialize(kb.snapshotId, ecosystems);
    const outDir = join(ctx.workDir, 'out');
    const cfgDir = join(ctx.workDir, 'cfg');
    await mkdir(outDir, { recursive: true });
    await mkdir(cfgDir, { recursive: true });
    // An explicit empty config overrides osv-scanner.toml files inside the scanned repository (ADR-025).
    await writeFile(join(cfgDir, 'osv-scanner.toml'), '');
    try {
      const capability = this.describe();
      const result = await ctx.sandbox.run(
        {
          name: containerName('osv', ctx.taskId),
          image: capability.image,
          args: [
            'scan',
            'source',
            '--offline',
            '--format',
            'json',
            '--all-packages',
            '--config',
            '/cfg/osv-scanner.toml',
            '--output-file',
            '/out/osv.json',
            '-r',
            '/src',
          ],
          env: { ...HOME_ENV, OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: '/db' },
          mounts: [
            { hostPath: ctx.source.root, containerPath: '/src', readOnly: true },
            { hostPath: dbDir, containerPath: '/db', readOnly: true },
            { hostPath: cfgDir, containerPath: '/cfg', readOnly: true },
            { hostPath: outDir, containerPath: '/out', readOnly: false },
          ],
          workdir: '/tmp',
          profile: 'scan',
          resources: capability.resources,
        },
        ctx.signal,
      );
      const raw = await readOutput(outDir, 'osv.json');
      if (raw === undefined) {
        if (result.exitCode === 128) {
          return {
            drafts: [],
            rawArtifacts: {},
            coverage: { ...emptyCoverage(files.length), completeness: 'COMPLETE' },
          };
        }
        throw new Error(`osv-scanner produced no output (exit ${result.exitCode}): ${tail(result.stderr)}`);
      }
      const output = JSON.parse(raw) as OsvOutput;
      const allowed = new Set(files.map((f) => f.path));
      const drafts: CandidateDraft[] = [];
      const analyzed = new Set<string>();
      const inventory: Array<{ name: string; version: string; ecosystem: string; purl: string; path: string }> = [];
      const uncovered: string[] = [];
      const ecosystemComplete = new Map<string, boolean>();
      const textCache = new Map<string, string>();

      for (const source of output.results ?? []) {
        const path = relativeToSrc(source.source.path);
        if (!allowed.has(path)) continue;
        analyzed.add(path);
        const text = textCache.get(path) ?? (await ctx.source.readText(path)) ?? '';
        textCache.set(path, text);
        for (const entry of source.packages ?? []) {
          const pkg = entry.package;
          const purl = cleanPurl(pkg.purl ?? `pkg:generic/${pkg.name}@${pkg.version}`);
          inventory.push({ name: pkg.name, version: pkg.version, ecosystem: pkg.ecosystem, purl, path });
          const covered =
            kb.ecosystems.includes(pkg.ecosystem) ||
            (await this.options.database.covers(kb.snapshotId, pkg.ecosystem, pkg.name));
          if (!covered) uncovered.push(`${pkg.ecosystem}/${pkg.name}`);
          ecosystemComplete.set(pkg.ecosystem, (ecosystemComplete.get(pkg.ecosystem) ?? true) && covered);
          const vulns = new Map((entry.vulnerabilities ?? []).map((v) => [v.id, v]));
          for (const group of entry.groups ?? []) {
            drafts.push(draftFor(pkg, purl, path, text, group, vulns));
          }
        }
      }

      const sbom = cycloneDx(inventory, ctx.snapshot.capturedAt, ctx.snapshot.contentManifestDigest);
      const sbomRef = await ctx.artifacts.put(JSON.stringify(sbom, null, 2), 'application/vnd.cyclonedx+json');
      const listRef = await ctx.artifacts.put(JSON.stringify([...analyzed].sort()), 'application/json');
      const toolErrors: Coverage['toolErrors'] = [];
      if (uncovered.length > 0) {
        toolErrors.push({
          tool: 'osv-scanner',
          message: `${uncovered.length} package(s) not covered by knowledge base ${kb.snapshotId} (e.g. ${uncovered.slice(0, 3).join(', ')}); run \`spinxsca kb sync\``,
        });
      }
      if (![0, 1, 128].includes(result.exitCode))
        toolErrors.push({ tool: 'osv-scanner', message: tail(result.stderr, 3) });
      const coverage: Coverage = {
        scope: 'FULL',
        completeness: toolErrors.length === 0 ? 'COMPLETE' : 'PARTIAL',
        files: { analyzed: analyzed.size, total: files.length, listDigest: listRef.digest },
        languages: [...ecosystemComplete.keys()].sort(),
        rules: {
          executed: [...ecosystemComplete.values()].filter(Boolean).length,
          bundleDigests: [kb.digest],
          ids: [...ecosystemComplete.entries()]
            .filter(([, ok]) => ok)
            .map(([eco]) => `osv.${eco}`)
            .sort(),
        },
        toolErrors,
      };
      ctx.logger.info(
        `osv-scanner analysed ${analyzed.size} manifests, ${inventory.length} packages, ${drafts.length} advisories`,
      );
      return {
        drafts,
        coverage,
        rawArtifacts: { json: await ctx.artifacts.put(raw, 'application/json'), sbom: sbomRef },
      };
    } finally {
      await rm(ctx.workDir, { recursive: true, force: true });
    }
  }
}

function draftFor(
  pkg: { name: string; version: string; ecosystem: string },
  purl: string,
  path: string,
  text: string,
  group: { ids: string[]; aliases?: string[]; max_severity?: string },
  vulns: Map<string, OsvVuln>,
): CandidateDraft {
  const records = group.ids.map((id) => vulns.get(id)).filter((v): v is OsvVuln => v !== undefined);
  const canonical = [...group.ids].sort().find((id) => id.startsWith('GHSA-')) ?? [...group.ids].sort()[0] ?? 'UNKNOWN';
  const primary = vulns.get(canonical) ?? records[0];
  const summary = primary?.summary?.trim() || `Known vulnerability ${canonical}`;
  const fixed = [
    ...new Set(
      records.flatMap((r) =>
        (r.affected ?? [])
          .filter((a) => a.package?.name === pkg.name)
          .flatMap((a) =>
            (a.ranges ?? [])
              .filter((x) => x.type !== 'GIT')
              .flatMap((x) => x.events.map((e) => e.fixed).filter(Boolean)),
          ),
      ),
    ),
  ] as string[];
  const cwes = [
    ...new Set(
      records
        .flatMap((r) => r.database_specific?.cwe_ids ?? [])
        .map(normalizeCwe)
        .filter(Boolean),
    ),
  ] as string[];
  const location = locatePackage(text, path, pkg.name, pkg.version);
  const purlNoVersion = purl.replace(/@[^@/]*$/, '');
  return {
    scanner: 'osv-scanner',
    ruleId: `osv.${pkg.ecosystem}`,
    ruleFamily: 'vulnerable-dependency',
    category: 'VULNERABLE_DEPENDENCY',
    cwe: ['CWE-1395', ...cwes.filter((c) => c !== 'CWE-1395')],
    title: `${pkg.name}@${pkg.version}: ${summary}`,
    message: `${summary}. ${pkg.name}@${pkg.version} is affected (${[...new Set([...group.ids, ...(group.aliases ?? [])])].sort().join(', ')}). ${
      fixed.length ? `Fixed in ${fixed.join(', ')}.` : 'No fixed version is published.'
    }`,
    severityHint: severityOf(group.max_severity, records),
    confidenceHint: 'HIGH' as Confidence,
    locations: [{ path, startLine: location.startLine, endLine: location.endLine, role: 'primary' }],
    package: { purl, ecosystem: pkg.ecosystem, name: pkg.name, version: pkg.version, manifestPath: path },
    vulnerabilityIds: [...new Set([...group.ids, ...(group.aliases ?? [])])].sort(),
    anchorHint: { symbol: `purl:${purlNoVersion}`, shape: `vuln:${canonical}` },
  };
}

function severityOf(maxSeverity: string | undefined, records: readonly OsvVuln[]): Severity {
  const score = Number(maxSeverity);
  if (maxSeverity && Number.isFinite(score) && score > 0) {
    if (score >= 9) return 'CRITICAL';
    if (score >= 7) return 'HIGH';
    if (score >= 4) return 'MEDIUM';
    return 'LOW';
  }
  const labels = records.map((r) => (r.database_specific?.severity ?? '').toUpperCase());
  if (labels.includes('CRITICAL')) return 'CRITICAL';
  if (labels.includes('HIGH')) return 'HIGH';
  if (labels.includes('MODERATE') || labels.includes('MEDIUM')) return 'MEDIUM';
  if (labels.includes('LOW')) return 'LOW';
  return 'MEDIUM';
}

/** Removes purl qualifiers such as ?source=PUBLIC_REGISTRY. */
function cleanPurl(purl: string): string {
  return purl.split('?')[0]?.split('#')[0] ?? purl;
}

function emptyCoverage(total: number, error?: string): Coverage {
  return {
    scope: 'FULL',
    completeness: 'PARTIAL',
    files: { analyzed: 0, total },
    languages: [],
    rules: { executed: 0, bundleDigests: [], ids: [] },
    toolErrors: error ? [{ tool: 'osv-scanner', message: error }] : [],
  };
}

/** CycloneDX 1.6 SBOM of the dependency inventory (ADR-014). Deterministic for a given snapshot. */
export function cycloneDx(
  inventory: ReadonlyArray<{ name: string; version: string; ecosystem: string; purl: string; path: string }>,
  timestamp: string,
  snapshotDigest: string,
): Record<string, unknown> {
  const hex = sha256Hex(snapshotDigest);
  const uuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-5${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
  const components = new Map<string, Record<string, unknown>>();
  for (const item of inventory) {
    const existing = components.get(item.purl);
    if (existing) {
      (existing.properties as Array<{ name: string; value: string }>).push({
        name: 'spinxsca:manifest',
        value: item.path,
      });
      continue;
    }
    const [group, name] =
      item.ecosystem === 'Maven' && item.name.includes(':') ? item.name.split(':') : [undefined, item.name];
    components.set(item.purl, {
      type: 'library',
      'bom-ref': item.purl,
      ...(group ? { group } : {}),
      name,
      version: item.version,
      purl: item.purl,
      properties: [
        { name: 'spinxsca:ecosystem', value: item.ecosystem },
        { name: 'spinxsca:manifest', value: item.path },
      ],
    });
  }
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${uuid}`,
    version: 1,
    metadata: {
      timestamp,
      tools: { components: [{ type: 'application', name: 'spinxsca', version: ENGINE_VERSION }] },
    },
    components: [...components.values()].sort((a, b) => String(a['bom-ref']).localeCompare(String(b['bom-ref']))),
  };
}
