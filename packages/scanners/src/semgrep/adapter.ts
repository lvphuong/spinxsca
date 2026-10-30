import { mkdir, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import type { ScannerAdapter, ScannerResult, ScannerRunContext } from '@spinxsca/core';
import { normalizeRelPath } from '@spinxsca/core';
import type { Coverage, RuleBundleRef, ScannerCapability, SnapshotFile } from '@spinxsca/schemas';
import { imageRef, PINNED_IMAGES, type PinnedImage } from '../images';
import { type LoadedRuleBundle, loadRuleBundle } from '../rule-bundle';
import { normalizeSemgrepResults, type SemgrepJson } from './normalize';

export const SEMGREP_ADAPTER_VERSION = '0.1.0';

const LANGUAGE_EXTENSIONS: Record<string, string[]> = {
  javascript: ['js', 'jsx', 'mjs', 'cjs'],
  typescript: ['ts', 'tsx', 'mts', 'cts'],
  python: ['py'],
  java: ['java'],
  go: ['go'],
  ruby: ['rb'],
  php: ['php'],
  csharp: ['cs'],
  kotlin: ['kt', 'kts'],
};

export interface SemgrepAdapterOptions {
  bundles: Array<{ id: string; dir: string }>;
  image?: PinnedImage;
  cpus?: number;
  memoryMb?: number;
  timeoutSec?: number;
  /** Per-file analysis timeout passed to semgrep. */
  perFileTimeoutSec?: number;
}

/** Semgrep CE adapter (docs/architecture/02 section 4). Runs only spinxsca-controlled local rule bundles. */
export class SemgrepAdapter implements ScannerAdapter {
  private loaded: Promise<LoadedRuleBundle[]> | undefined;
  private readonly image: PinnedImage;

  constructor(private readonly options: SemgrepAdapterOptions) {
    if (options.bundles.length === 0) throw new Error('semgrep adapter needs at least one rule bundle');
    this.image = options.image ?? PINNED_IMAGES.semgrep;
  }

  describe(): ScannerCapability {
    return {
      id: 'semgrep',
      adapterVersion: SEMGREP_ADAPTER_VERSION,
      toolVersion: this.image.toolVersion,
      image: imageRef(this.image),
      capabilities: ['SAST'],
      languages: Object.keys(LANGUAGE_EXTENSIONS),
      scanModes: ['FULL', 'INCREMENTAL', 'TARGETED'],
      outputs: ['NATIVE_JSON', 'SARIF'],
      requiresNetwork: false,
      requiresBuild: false,
      resources: {
        cpus: this.options.cpus ?? 2,
        memoryMb: this.options.memoryMb ?? 4096,
        timeoutSec: this.options.timeoutSec ?? 1800,
      },
    };
  }

  async ruleBundles(): Promise<RuleBundleRef[]> {
    return (await this.bundles()).map((b) => b.ref);
  }

  applies(files: readonly SnapshotFile[]): boolean {
    const extensions = new Set(Object.values(LANGUAGE_EXTENSIONS).flat());
    return files.some((f) => extensions.has(extensionOf(f.path)));
  }

  async run(ctx: ScannerRunContext): Promise<ScannerResult> {
    const bundles = await this.bundles();
    const capability = this.describe();
    const outDir = join(ctx.workDir, 'out');
    await mkdir(outDir, { recursive: true });
    try {
      const args = [
        'semgrep',
        'scan',
        ...bundles.flatMap((b) => ['--config', `/rules/${b.ref.id}`]),
        '--metrics=off',
        '--disable-version-check',
        '--oss-only',
        '--no-rewrite-rule-ids',
        '--quiet',
        '--timeout',
        String(this.options.perFileTimeoutSec ?? 30),
        '--jobs',
        String(Math.max(1, Math.floor(capability.resources.cpus))),
        '--json-output=/out/result.json',
        '--sarif-output=/out/result.sarif',
        ...['.spinxsca', '.git', ...ctx.exclude].flatMap((pattern) => ['--exclude', pattern]),
        ...(ctx.scope ? ctx.scope.map((p) => `/src/${p}`) : ['.']),
      ];
      const result = await ctx.sandbox.run(
        {
          name: `spinxsca-${ctx.taskId.replace(/[^a-zA-Z0-9_.-]/g, '-')}`,
          image: capability.image,
          args,
          env: {
            HOME: '/tmp',
            XDG_CONFIG_HOME: '/tmp',
            XDG_CACHE_HOME: '/tmp',
            SEMGREP_SEND_METRICS: 'off',
            SEMGREP_ENABLE_VERSION_CHECK: '0',
          },
          mounts: [
            { hostPath: ctx.source.root, containerPath: '/src', readOnly: true },
            ...bundles.map((b) => ({ hostPath: b.dir, containerPath: `/rules/${b.ref.id}`, readOnly: true })),
            { hostPath: outDir, containerPath: '/out', readOnly: false },
          ],
          workdir: '/src',
          profile: 'scan',
          resources: capability.resources,
        },
        ctx.signal,
      );

      const rawJson = await readFile(join(outDir, 'result.json'), 'utf8').catch(() => undefined);
      if (rawJson === undefined) {
        const reason = result.timedOut ? 'timed out' : `exit code ${result.exitCode}`;
        throw new Error(`semgrep produced no output (${reason}): ${tail(result.stderr)}`);
      }
      const json = JSON.parse(rawJson) as SemgrepJson;
      const rawSarif = await readFile(join(outDir, 'result.sarif'), 'utf8').catch(() => undefined);

      const snapshotFiles = JSON.parse(await ctx.artifacts.getText(ctx.snapshot.fileListDigest)) as SnapshotFile[];
      const allowed = new Set(snapshotFiles.map((f) => f.path));
      const analyzed = [
        ...new Set((json.paths?.scanned ?? []).map((p) => normalizeRelPath(p.replace(/^\/src\/?/, '')))),
      ]
        .filter((p) => allowed.has(p))
        .sort();
      const ruleOwner = new Map<string, string>();
      for (const bundle of bundles) for (const id of bundle.ruleIds) ruleOwner.set(id, bundle.ref.id);

      const drafts = normalizeSemgrepResults(json, { bundleOf: (id) => ruleOwner.get(id), allowedPaths: allowed });
      const errors = (json.errors ?? []).map((e) => ({
        tool: 'semgrep',
        message: (e.message ?? JSON.stringify(e.type ?? 'error')).slice(0, 500),
        ...(e.path ? { path: normalizeRelPath(e.path) } : {}),
      }));
      const fatal = (json.errors ?? []).some((e) => (e.level ?? '').toLowerCase() === 'error' && !e.path);
      const listRef = await ctx.artifacts.put(JSON.stringify(analyzed), 'application/json');
      const coverage: Coverage = {
        scope: ctx.scope ? 'INCREMENTAL' : 'FULL',
        completeness: result.timedOut || fatal || ![0, 1].includes(result.exitCode) ? 'PARTIAL' : 'COMPLETE',
        files: { analyzed: analyzed.length, total: snapshotFiles.length, listDigest: listRef.digest },
        languages: [...new Set(analyzed.map(languageOf).filter((l): l is string => l !== undefined))].sort(),
        rules: {
          executed: bundles.reduce((n, b) => n + b.ruleIds.length, 0),
          bundleDigests: bundles.map((b) => b.ref.digest),
          ids: bundles.flatMap((b) => b.ruleIds.map((id) => `${b.ref.id}.${id}`)).sort(),
        },
        toolErrors: errors,
      };
      const rawArtifacts: ScannerResult['rawArtifacts'] = {
        json: await ctx.artifacts.put(rawJson, 'application/json'),
      };
      if (rawSarif) rawArtifacts.sarif = await ctx.artifacts.put(rawSarif, 'application/sarif+json');
      ctx.logger.info(`semgrep analysed ${analyzed.length} files, ${drafts.length} results`, {
        exitCode: result.exitCode,
        durationMs: result.durationMs,
      });
      return { drafts, coverage, rawArtifacts };
    } finally {
      await rm(ctx.workDir, { recursive: true, force: true });
    }
  }

  private bundles(): Promise<LoadedRuleBundle[]> {
    this.loaded ??= Promise.all(this.options.bundles.map((b) => loadRuleBundle(b.id, b.dir)));
    return this.loaded;
  }
}

function extensionOf(path: string): string {
  return path.slice(path.lastIndexOf('.') + 1).toLowerCase();
}

function languageOf(path: string): string | undefined {
  const ext = extensionOf(path);
  return Object.entries(LANGUAGE_EXTENSIONS).find(([, exts]) => exts.includes(ext))?.[0];
}

function tail(text: string, lines = 15): string {
  return text.trim().split('\n').slice(-lines).join('\n');
}
