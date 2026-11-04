import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  type ActivityRunnerDeps,
  type ArtifactStore,
  type CandidateDraft,
  type KnowledgeBaseRef,
  type Logger,
  newId,
  type ProbePort,
  type ProbeRequest,
  type ProbeResult,
  probeActivity,
  runActivity,
  type SandboxRunner,
  type ScannerAdapter,
  type ScannerResult,
  type SourceTree,
} from '@spinxsca/core';
import type { SourceSnapshot } from '@spinxsca/schemas';
import type { PinnedImage } from './images';
import { SemgrepAdapter } from './semgrep/adapter';
import { reproducesSeed, validateAgentRules } from './semgrep/agent-rule';

export interface ProbePortDeps {
  runner: ActivityRunnerDeps;
  scanId: string;
  snapshot: SourceSnapshot;
  source: SourceTree;
  sandbox: SandboxRunner;
  artifacts: ArtifactStore;
  logger: Logger;
  exclude: readonly string[];
  /** Configured scanners an agent may re-run (by capability id). */
  adapters: ReadonlyMap<string, ScannerAdapter>;
  knowledgeBase?: KnowledgeBaseRef;
  /** Host directory for rule files and scanner outputs of probes. */
  workRoot: string;
  semgrepImage?: PinnedImage;
}

interface ProbeOutput {
  drafts: CandidateDraft[];
  coverage?: ScannerResult['coverage'];
}

/**
 * Probe port over the configured scanners (ADR-043). Agent rules run through the same Semgrep
 * adapter, image and sandbox as the deterministic scan, with host-chosen paths.
 */
export function createProbePort(deps: ProbePortDeps): ProbePort {
  const runScanner = async (adapter: ScannerAdapter, taskId: string, paths: readonly string[] | undefined) => {
    const workDir = join(deps.workRoot, `${taskId}-${newId('w')}`);
    await mkdir(workDir, { recursive: true });
    return adapter.run({
      scanId: deps.scanId,
      taskId,
      snapshot: deps.snapshot,
      source: deps.source,
      exclude: deps.exclude,
      workDir,
      sandbox: deps.sandbox,
      artifacts: deps.artifacts,
      logger: deps.logger,
      ...(deps.knowledgeBase ? { knowledgeBase: deps.knowledgeBase } : {}),
      ...(paths?.length ? { scope: paths } : {}),
    });
  };

  return {
    scanners: [...deps.adapters.keys()].sort(),
    async run(request: ProbeRequest): Promise<ProbeResult> {
      if (request.kind === 'scanner') {
        const adapter = deps.adapters.get(request.scanner);
        if (!adapter)
          return { taskId: '', reused: false, drafts: [], problems: [`unknown scanner ${request.scanner}`] };
        const activity = probeActivity<ProbeRequest, ProbeOutput>(
          `probe:${request.scanner}`,
          (r) => ({ r, bundles: adapter.describe().image }),
          async (_input, ctx) => {
            const result = await runScanner(adapter, ctx.taskId, request.paths);
            return { output: { drafts: result.drafts, coverage: result.coverage }, coverage: result.coverage };
          },
        );
        const out = await runActivity(deps.runner, deps.scanId, activity, request, { scannerId: request.scanner });
        return {
          taskId: out.task.taskId,
          reused: out.reused,
          drafts: out.output?.drafts ?? [],
          ...(out.output?.coverage ? { coverage: out.output.coverage } : {}),
          problems: out.task.error ? [out.task.error] : [],
        };
      }
      const check = validateAgentRules(request.yaml);
      if (!check.ok || !check.yaml) return { taskId: '', reused: false, drafts: [], problems: check.problems };
      const rules = check.yaml;
      const activity = probeActivity<ProbeRequest, ProbeOutput>(
        'probe:semgrep-rule',
        () => ({ rules, paths: request.paths ?? [] }),
        async (_input, ctx) => {
          const dir = join(deps.workRoot, `rules-${ctx.taskId}`);
          await mkdir(dir, { recursive: true });
          await writeFile(join(dir, 'agent.yaml'), rules);
          const adapter = new SemgrepAdapter({
            bundles: [{ id: 'ai-probe', dir }],
            ...(deps.semgrepImage ? { image: deps.semgrepImage } : {}),
            timeoutSec: 300,
          });
          const result = await runScanner(adapter, ctx.taskId, request.paths);
          const drafts = result.drafts.map((d) => ({
            ...d,
            scanner: 'ai-probe',
            ruleId: d.ruleId.replace(/^ai-probe\.ai-probe\./, 'ai-probe.'),
          }));
          return { output: { drafts, coverage: result.coverage }, coverage: result.coverage };
        },
      );
      const out = await runActivity(deps.runner, deps.scanId, activity, request, { scannerId: 'ai-probe' });
      const drafts = out.output?.drafts ?? [];
      const reproduced = request.seed ? reproducesSeed(drafts, request.seed) : undefined;
      return {
        taskId: out.task.taskId,
        reused: out.reused,
        // A variant rule that misses its own seed proves nothing; its other matches are discarded.
        drafts: reproduced === false ? [] : drafts,
        ...(out.output?.coverage ? { coverage: out.output.coverage } : {}),
        problems: [
          ...(out.task.error ? [out.task.error] : []),
          ...(reproduced === false
            ? ['the rule did not reproduce the seed finding; refine it before looking for variants']
            : []),
        ],
        ...(reproduced !== undefined ? { reproducedSeed: reproduced } : {}),
      };
    },
  };
}
