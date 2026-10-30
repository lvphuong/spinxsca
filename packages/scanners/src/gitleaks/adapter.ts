import { mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { CandidateDraft, ScannerAdapter, ScannerResult, ScannerRunContext } from '@spinxsca/core';
import { sha256, sha256Hex } from '@spinxsca/core';
import type { Coverage, RuleBundleRef, ScannerCapability, SnapshotFile } from '@spinxsca/schemas';
import { imageRef, PINNED_IMAGES, type PinnedImage } from '../images';
import { containerName, HOME_ENV, readOutput, relativeToSrc, snapshotFiles, tail } from '../shared';

export const GITLEAKS_ADAPTER_VERSION = '0.1.0';
const MAX_TARGET_MB = 5;

/**
 * Operator-owned configuration: the embedded default rule set plus exclusions for spinxsca state.
 * Passing it explicitly means a .gitleaks.toml inside the scanned repository is never used (ADR-025).
 */
export const GITLEAKS_CONFIG = `title = "spinxsca"

[extend]
useDefault = true

[allowlist]
description = "spinxsca state and VCS metadata"
paths = ['''(^|/)\\.spinxsca/''', '''(^|/)\\.git/''']
`;

interface GitleaksFinding {
  RuleID: string;
  Description?: string;
  File: string;
  StartLine: number;
  EndLine: number;
  Tags?: string[];
}

/** Secret detection with gitleaks (docs/architecture/02 section 4.1). */
export class GitleaksAdapter implements ScannerAdapter {
  private readonly image: PinnedImage;

  constructor(options: { image?: PinnedImage } = {}) {
    this.image = options.image ?? PINNED_IMAGES.gitleaks;
  }

  describe(): ScannerCapability {
    return {
      id: 'gitleaks',
      adapterVersion: GITLEAKS_ADAPTER_VERSION,
      toolVersion: this.image.toolVersion,
      image: imageRef(this.image),
      capabilities: ['SECRETS'],
      languages: ['any'],
      scanModes: ['FULL'],
      outputs: ['NATIVE_JSON'],
      requiresNetwork: false,
      requiresBuild: false,
      resources: { cpus: 2, memoryMb: 1024, timeoutSec: 900 },
    };
  }

  async ruleBundles(): Promise<RuleBundleRef[]> {
    return [
      {
        id: 'gitleaks',
        version: this.image.toolVersion,
        digest: sha256(`gitleaks-default@${this.image.toolVersion}\n${GITLEAKS_CONFIG}`),
        ruleCount: 0,
      },
    ];
  }

  applies(files: readonly SnapshotFile[]): boolean {
    return files.length > 0;
  }

  async run(ctx: ScannerRunContext): Promise<ScannerResult> {
    const files = await snapshotFiles(ctx);
    const outDir = join(ctx.workDir, 'out');
    const cfgDir = join(ctx.workDir, 'cfg');
    await mkdir(outDir, { recursive: true });
    await mkdir(cfgDir, { recursive: true });
    await writeFile(join(cfgDir, 'gitleaks.toml'), GITLEAKS_CONFIG);
    await writeFile(join(cfgDir, 'gitleaksignore'), '');
    try {
      const capability = this.describe();
      const result = await ctx.sandbox.run(
        {
          name: containerName('gitleaks', ctx.taskId),
          image: capability.image,
          args: [
            'dir',
            '/src',
            '--config',
            '/cfg/gitleaks.toml',
            '--gitleaks-ignore-path',
            '/cfg/gitleaksignore',
            '--ignore-gitleaks-allow',
            '--redact',
            '--report-format',
            'json',
            '--report-path',
            '/out/gitleaks.json',
            '--exit-code',
            '0',
            '--no-banner',
            '--log-level',
            'error',
            '--max-target-megabytes',
            String(MAX_TARGET_MB),
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
      const raw = await readOutput(outDir, 'gitleaks.json');
      if (raw === undefined)
        throw new Error(`gitleaks produced no output (exit ${result.exitCode}): ${tail(result.stderr)}`);
      const findings = JSON.parse(raw) as GitleaksFinding[];
      const allowed = new Set(files.map((f) => f.path));
      const drafts: CandidateDraft[] = [];
      for (const finding of findings) {
        const path = relativeToSrc(finding.File);
        if (!allowed.has(path)) continue;
        const text = (await ctx.source.readText(path)) ?? '';
        drafts.push(draftFor(finding, path, text));
      }
      const analyzed = files.filter((f) => f.size <= MAX_TARGET_MB * 1024 * 1024).map((f) => f.path);
      const listRef = await ctx.artifacts.put(JSON.stringify(analyzed), 'application/json');
      const coverage: Coverage = {
        scope: 'FULL',
        completeness: result.exitCode === 0 && !result.timedOut ? 'COMPLETE' : 'PARTIAL',
        files: { analyzed: analyzed.length, total: files.length, listDigest: listRef.digest },
        languages: ['any'],
        rules: { executed: 1, bundleDigests: (await this.ruleBundles()).map((b) => b.digest), ids: ['gitleaks.*'] },
        toolErrors: result.exitCode === 0 ? [] : [{ tool: 'gitleaks', message: tail(result.stderr, 3) }],
      };
      ctx.logger.info(`gitleaks reported ${drafts.length} secrets`);
      // The report is already redacted by gitleaks (--redact).
      return { drafts, coverage, rawArtifacts: { json: await ctx.artifacts.put(raw, 'application/json') } };
    } finally {
      await rm(ctx.workDir, { recursive: true, force: true });
    }
  }
}

/**
 * Locates the secret token on the reported line(s). Only its position and a truncated hash leave
 * this function; the value itself is never stored.
 */
export function secretSpan(lineText: string): { startColumn: number; endColumn: number; token: string } | undefined {
  const quoted = [...lineText.matchAll(/(["'`])([^"'`\s]{8,})\1/g)].map((m) => ({
    token: m[2] as string,
    index: (m.index ?? 0) + 1,
  }));
  const bare = [...lineText.matchAll(/[A-Za-z0-9+/=_\-.:@]{16,}/g)].map((m) => ({ token: m[0], index: m.index ?? 0 }));
  const best = [...(quoted.length ? quoted : bare)].sort((a, b) => b.token.length - a.token.length)[0];
  if (!best) return undefined;
  return { startColumn: best.index + 1, endColumn: best.index + 1 + best.token.length, token: best.token };
}

function draftFor(finding: GitleaksFinding, path: string, text: string): CandidateDraft {
  const lines = text.split(/\r?\n/);
  const start = Math.max(1, finding.StartLine);
  const end = Math.max(start, finding.EndLine);
  const span = start === end ? secretSpan(lines[start - 1] ?? '') : undefined;
  const material = span?.token ?? lines.slice(start - 1, end).join('\n');
  const generic = finding.RuleID.startsWith('generic');
  return {
    scanner: 'gitleaks',
    ruleId: `gitleaks.${finding.RuleID}`,
    ruleFamily: 'hardcoded-secret',
    category: 'HARDCODED_SECRET',
    cwe: ['CWE-798'],
    title: `Hardcoded secret (${finding.RuleID})`,
    message: `${finding.Description ?? 'Secret detected'}. Rotate the credential and load it from a secret manager or the environment instead of source code.`,
    severityHint: generic ? 'MEDIUM' : 'HIGH',
    confidenceHint: generic ? 'MEDIUM' : 'HIGH',
    locations: [
      {
        path,
        startLine: start,
        endLine: end,
        ...(span ? { startColumn: span.startColumn, endColumn: span.endColumn } : {}),
        role: 'primary',
      },
    ],
    anchorHint: { symbol: `secret:${finding.RuleID}`, shape: `secret:${sha256Hex(material).slice(0, 16)}` },
  };
}
