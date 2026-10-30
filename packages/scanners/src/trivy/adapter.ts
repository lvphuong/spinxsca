import { mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { CandidateDraft, ScannerAdapter, ScannerResult, ScannerRunContext } from '@spinxsca/core';
import { sha256, sha256Hex } from '@spinxsca/core';
import {
  type Coverage,
  type RuleBundleRef,
  type ScannerCapability,
  SEVERITY_RANK,
  type Severity,
  type SnapshotFile,
} from '@spinxsca/schemas';
import { imageRef, PINNED_IMAGES, type PinnedImage } from '../images';
import { containerName, extensionOf, HOME_ENV, readOutput, relativeToSrc, snapshotFiles, tail } from '../shared';

export const TRIVY_ADAPTER_VERSION = '0.1.0';
const CONFIG_FILE =
  /(^|\/)(Dockerfile[^/]*|[^/]*\.dockerfile|Containerfile|docker-compose[^/]*\.ya?ml|compose\.ya?ml|Chart\.yaml)$/i;
const CONFIG_EXT = new Set(['yaml', 'yml', 'json', 'tf', 'tfvars', 'hcl', 'bicep']);
/** Checks about running as root or with elevated privileges. */
const PRIVILEGE_CHECKS = new Set(['DS-0002', 'KSV-0001', 'KSV-0012', 'KSV-0017', 'KSV-0014', 'KSV-0020', 'KSV-0021']);

interface TrivyMisconfig {
  ID: string;
  Title: string;
  Message?: string;
  Resolution?: string;
  Severity: string;
  Status: string;
  PrimaryURL?: string;
  CauseMetadata?: { StartLine?: number; EndLine?: number; Code?: { Lines?: Array<{ Content?: string }> } };
}

/** Infrastructure-as-code misconfiguration checks with Trivy's embedded check bundle (offline). */
export class TrivyAdapter implements ScannerAdapter {
  private readonly image: PinnedImage;
  private readonly minSeverity: Severity;

  constructor(options: { image?: PinnedImage; minSeverity?: Severity } = {}) {
    this.image = options.image ?? PINNED_IMAGES.trivy;
    this.minSeverity = options.minSeverity ?? 'MEDIUM';
  }

  describe(): ScannerCapability {
    return {
      id: 'trivy',
      adapterVersion: TRIVY_ADAPTER_VERSION,
      toolVersion: this.image.toolVersion,
      image: imageRef(this.image),
      capabilities: ['IAC'],
      languages: ['dockerfile', 'kubernetes', 'terraform', 'cloudformation', 'helm'],
      scanModes: ['FULL'],
      outputs: ['NATIVE_JSON'],
      requiresNetwork: false,
      requiresBuild: false,
      resources: { cpus: 2, memoryMb: 2048, timeoutSec: 900 },
    };
  }

  /** The embedded checks are versioned by the tool; the severity threshold is part of the bundle identity. */
  async ruleBundles(): Promise<RuleBundleRef[]> {
    return [
      {
        id: 'trivy',
        version: this.image.toolVersion,
        digest: sha256(`trivy-embedded-checks@${this.image.toolVersion}|min=${this.minSeverity}`),
        ruleCount: 0,
      },
    ];
  }

  applies(files: readonly SnapshotFile[]): boolean {
    return files.some((f) => CONFIG_FILE.test(f.path) || CONFIG_EXT.has(extensionOf(f.path)));
  }

  async run(ctx: ScannerRunContext): Promise<ScannerResult> {
    const files = await snapshotFiles(ctx);
    const outDir = join(ctx.workDir, 'out');
    const cfgDir = join(ctx.workDir, 'cfg');
    await mkdir(outDir, { recursive: true });
    await mkdir(cfgDir, { recursive: true });
    // Explicit operator files so trivy.yaml / .trivyignore inside the repository are never used (ADR-025).
    await writeFile(join(cfgDir, 'trivy.yaml'), '{}\n');
    await writeFile(join(cfgDir, 'trivyignore'), '');
    try {
      const capability = this.describe();
      const result = await ctx.sandbox.run(
        {
          name: containerName('trivy', ctx.taskId),
          image: capability.image,
          args: [
            'fs',
            '--scanners',
            'misconfig',
            '--skip-check-update',
            '--skip-db-update',
            '--offline-scan',
            '--cache-dir',
            '/tmp/trivy',
            '--include-non-failures',
            '--config',
            '/cfg/trivy.yaml',
            '--ignorefile',
            '/cfg/trivyignore',
            '--skip-dirs',
            '/src/.spinxsca',
            '--skip-dirs',
            '/src/.git',
            '--format',
            'json',
            '--output',
            '/out/trivy.json',
            '--quiet',
            '/src',
          ],
          env: HOME_ENV,
          mounts: [
            { hostPath: ctx.source.root, containerPath: '/src', readOnly: true },
            { hostPath: cfgDir, containerPath: '/cfg', readOnly: true },
            { hostPath: outDir, containerPath: '/out', readOnly: false },
          ],
          workdir: '/tmp',
          profile: 'scan',
          resources: capability.resources,
        },
        ctx.signal,
      );
      const raw = await readOutput(outDir, 'trivy.json');
      if (raw === undefined)
        throw new Error(`trivy produced no output (exit ${result.exitCode}): ${tail(result.stderr)}`);
      const output = JSON.parse(raw) as {
        Results?: Array<{ Target: string; Class?: string; Misconfigurations?: TrivyMisconfig[] }>;
      };
      const allowed = new Set(files.map((f) => f.path));
      const analyzed = new Set<string>();
      const drafts: CandidateDraft[] = [];
      for (const target of output.Results ?? []) {
        if (target.Class !== 'config') continue;
        const path = relativeToSrc(target.Target);
        if (!allowed.has(path)) continue;
        analyzed.add(path);
        for (const m of target.Misconfigurations ?? []) {
          if (m.Status !== 'FAIL') continue;
          const severity = toSeverity(m.Severity);
          if (SEVERITY_RANK[severity] < SEVERITY_RANK[this.minSeverity]) continue;
          drafts.push(draftFor(m, path, severity));
        }
      }
      const listRef = await ctx.artifacts.put(JSON.stringify([...analyzed].sort()), 'application/json');
      const coverage: Coverage = {
        scope: 'FULL',
        completeness: result.exitCode === 0 && !result.timedOut ? 'COMPLETE' : 'PARTIAL',
        files: { analyzed: analyzed.size, total: files.length, listDigest: listRef.digest },
        languages: capability.languages,
        rules: { executed: 1, bundleDigests: (await this.ruleBundles()).map((b) => b.digest), ids: ['trivy.*'] },
        toolErrors: result.exitCode === 0 ? [] : [{ tool: 'trivy', message: tail(result.stderr, 3) }],
      };
      ctx.logger.info(`trivy analysed ${analyzed.size} config files, ${drafts.length} misconfigurations`);
      return { drafts, coverage, rawArtifacts: { json: await ctx.artifacts.put(raw, 'application/json') } };
    } finally {
      await rm(ctx.workDir, { recursive: true, force: true });
    }
  }
}

function draftFor(m: TrivyMisconfig, path: string, severity: Severity): CandidateDraft {
  const start = m.CauseMetadata?.StartLine && m.CauseMetadata.StartLine > 0 ? m.CauseMetadata.StartLine : 1;
  const end = Math.max(start, m.CauseMetadata?.EndLine ?? start);
  const cause = (m.CauseMetadata?.Code?.Lines ?? []).map((l) => (l.Content ?? '').replace(/\s+/g, '')).join('\n');
  return {
    scanner: 'trivy',
    ruleId: `trivy.${m.ID}`,
    ruleFamily: `misconfig.${m.ID}`,
    category: 'INSECURE_CONFIGURATION',
    cwe: PRIVILEGE_CHECKS.has(m.ID) ? ['CWE-250', 'CWE-16'] : ['CWE-16'],
    title: m.Title,
    message: `${m.Message ?? m.Title}${m.Resolution ? ` Resolution: ${m.Resolution}` : ''}${m.PrimaryURL ? ` (${m.PrimaryURL})` : ''}`,
    severityHint: severity,
    confidenceHint: 'HIGH',
    locations: [{ path, startLine: start, endLine: end, role: 'primary' }],
    anchorHint: { symbol: `check:${m.ID}`, shape: cause ? `cause:${sha256Hex(cause).slice(0, 16)}` : 'file' },
  };
}

function toSeverity(value: string): Severity {
  const upper = value.toUpperCase();
  return upper === 'CRITICAL' || upper === 'HIGH' || upper === 'MEDIUM' || upper === 'LOW' ? upper : 'INFO';
}
