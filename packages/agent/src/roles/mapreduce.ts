import {
  applyRedactions,
  type CandidateDraft,
  type InvestigationSubject,
  type MapOutput,
  type MapReduceInvestigator,
  type ReconOutput,
  type ReduceInput,
  type ReduceOutput,
  redactSecrets,
  renderDigest,
  type ShardSubject,
  type SourceTree,
} from '@spinxsca/core';
import {
  type AgentRunRecord,
  type AiContextConfig,
  type AiFinding,
  type AttackChain,
  type Confidence,
  type GroundTruth,
  InvestigationResult,
  InvestigationResultLite,
  ReconDeliverable,
  ReduceResult,
  SEVERITY_RANK,
  type Severity,
} from '@spinxsca/schemas';
import {
  acceptedRisksVar,
  closedEndedProblems,
  coverageOf,
  emptyGroundTruth,
  isDuplicate,
  mergeOperatorContext,
  renderGroundTruth,
  renderOperatorContext,
  sliceFor,
  validateGroundTruth,
} from '../ground-truth';
import { costOf } from '../llm/pricing';
import type { Effort, LlmProvider } from '../llm/types';
import { compileDataPolicy } from '../policy';
import type { PromptBundle } from '../prompts/bundle';
import type { CompactionOptions } from '../runtime/compaction';
import { contextBudgetFor } from '../runtime/context-budget';
import { type AgentBudget, type AgentRunResult, DEFAULT_BUDGET, runAgent } from '../runtime/loop';
import { promptBudgetFor } from '../runtime/prompt-budget';
import { runStructured } from '../runtime/structured';
import { llmSummarizer } from '../runtime/summarizer';
import { checkCitations, createCodeTools } from '../tools/code-tools';
import { createGraphTools } from '../tools/graph-tools';
import { createRepoMapTool } from '../tools/repo-map-tool';
import { EXPLAIN_POLICY_VERSION, toRecord } from './explainer';
import type { ReconOptions } from './investigator';
import { toDraft } from './investigator';
import { liftLiteResult, useLiteDeliverables } from './lite';

export interface AgentMapReduceOptions {
  /** Providers per role (ADR-053); `deep` serves recon and is the fallback for the others. */
  providers: { deep: () => LlmProvider; map?: () => LlmProvider; reduce?: () => LlmProvider };
  prompts: PromptBundle;
  effort?: Effort;
  budget?: Partial<AgentBudget>;
  recon?: ReconOptions;
  context?: AiContextConfig;
  /** Concurrent shard workers (defaults from the map endpoint). */
  mapWorkers?: number;
  /** Data policy (docs/architecture/06 section 3.2): paths never sent to a model. */
  excludePaths?: readonly string[];
  /** Model writing compaction summaries (ADR-056). */
  summarizeProvider?: () => LlmProvider;
}

const CONFIDENCE_RANK: Record<Confidence, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };
const MAX_SIGNALS_IN_PROMPT = 60;
const MAX_REDUCER_ROWS = 300;

/**
 * Sharded investigation (ADR-055). Recon runs once over the repository; every shard gets a mapper
 * that only reports findings whose primary line is in a file it owns; the reducer sees the mappers'
 * claims (never code), merges duplicates, reconciles severity, composes attack chains and ranks.
 * The host keeps identity: refs `F-n` are assigned here, the reducer can only refer to them.
 */
export class AgentMapReduceInvestigator implements MapReduceInvestigator {
  readonly info: MapReduceInvestigator['info'];
  private readonly mapProvider: () => LlmProvider;
  private readonly reduceProvider: () => LlmProvider;
  private readonly allows: (path: string) => boolean;

  constructor(private readonly options: AgentMapReduceOptions) {
    this.mapProvider = options.providers.map ?? options.providers.deep;
    this.reduceProvider = options.providers.reduce ?? options.providers.deep;
    this.allows = compileDataPolicy({ excludePaths: options.excludePaths ?? [] });
    const deep = options.providers.deep();
    this.info = {
      provider: deep.id,
      model: deep.model,
      promptBundleDigest: options.prompts.digest,
      policyVersion: `${EXPLAIN_POLICY_VERSION}+mapreduce-v1`,
      mapModel: this.mapProvider().model,
      reduceModel: this.reduceProvider().model,
    };
  }

  mapEffectiveWindow(): number {
    return contextBudgetFor(this.mapProvider().capabilities(), DEFAULT_BUDGET).effective;
  }

  private summarizer(): { summarizer?: NonNullable<CompactionOptions['summarize']> } {
    return this.options.summarizeProvider
      ? {
          summarizer: llmSummarizer(this.options.summarizeProvider, {
            system: this.options.prompts.render('summarize'),
          }),
        }
      : {};
  }

  mapWorkers(): number {
    if (this.options.mapWorkers) return this.options.mapWorkers;
    const p = this.mapProvider();
    if (p.id === 'ollama') return 1;
    if (p.id === 'openai-compatible') return 2;
    return 4;
  }

  private record<O>(
    role: AgentRunRecord['role'],
    provider: LlmProvider,
    startedAt: string,
    result: AgentRunResult<O>,
    scanId: string,
  ): AgentRunRecord {
    return toRecord(result, { role, provider, promptBundleDigest: this.options.prompts.digest, startedAt, scanId });
  }

  async recon(
    subject: InvestigationSubject,
    source: SourceTree,
    options: { maxCostUsd: number; signal?: AbortSignal; onRun?: (run: AgentRunRecord) => Promise<void> },
  ): Promise<ReconOutput> {
    const context = subject.context ?? this.options.context;
    const vars = { accepted_risks: acceptedRisksVar(context) };
    const recon = { enabled: true, ...this.options.recon };
    const base = (gt: GroundTruth): ReconOutput => ({
      groundTruth: mergeOperatorContext(gt, context),
      summary: '',
      runs: [],
      costUsd: 0,
      deferred: [],
      infraFailures: [],
    });
    if (!recon.enabled) return base(emptyGroundTruth());
    const ctx = { source, paths: subject.snapshotPaths.filter(this.allows), redactions: subject.redactions };
    const tools = [
      ...createCodeTools(ctx),
      ...(subject.graph ? createGraphTools(subject.graph) : []),
      ...(subject.digest ? [createRepoMapTool(subject.digest)] : []),
    ];
    const provider = this.options.providers.deep();
    const pb = promptBudgetFor(contextBudgetFor(provider.capabilities(), DEFAULT_BUDGET), 'recon');
    const startedAt = new Date().toISOString();
    const scannerSummary = subject.scannerCandidates.length
      ? subject.scannerCandidates
          .slice(0, 60)
          .map((c) => `- ${c.category} ${c.locations[0]?.path}:${c.locations[0]?.startLine} (${c.ruleId})`)
          .join('\n')
      : '(none)';
    const stats = `Files: ${subject.snapshotPaths.length}. Endpoints discovered: ${subject.graph?.endpoints().length ?? 'unknown (no index)'}. The investigation is sharded: packets are informational, ground truth drives every shard.`;
    const result = await runAgent({
      role: 'recon',
      provider,
      tools,
      ...(this.options.effort ? { effort: this.options.effort } : {}),
      ...(options.signal ? { signal: options.signal } : {}),
      ...this.summarizer(),
      scanId: subject.scan.scanId,
      costOf,
      system: this.options.prompts.render('recon', vars),
      prompt: [
        'Reconnoitre this codebase: classify it, build the threat model and extract the ground truth.',
        '',
        stats,
        subject.digest ? renderDigest(subject.digest, { depth: 2, maxChars: pb.digest }) : '',
        '',
        `Scanner findings already recorded:\n${scannerSummary}`,
        renderOperatorContext(context),
      ]
        .filter(Boolean)
        .join('\n\n'),
      submit: {
        name: 'submit_recon',
        description: 'Submit the threat model, packets and ground truth. Call exactly once.',
        output: ReconDeliverable,
        validate: async (d) => [
          ...(await checkCitations(
            ctx,
            d.threatModel.packets.flatMap((p) =>
              p.entryPoints.map((e) => ({ path: e.path, startLine: e.line, endLine: e.line })),
            ),
          )),
          ...(await validateGroundTruth(d.groundTruth, ctx, {
            packetIds: new Set(d.threatModel.packets.map((p) => p.packetId)),
          })),
        ],
      },
      budget: {
        maxSteps: 30,
        maxToolCalls: 90,
        maxOutputTokens: 32_000,
        maxTotalTokens: 700_000,
        ...this.options.budget,
      },
      maxCostUsd: options.maxCostUsd,
    });
    const run = this.record('recon', provider, startedAt, result, subject.scan.scanId);
    await options.onRun?.(run);
    const out = base(result.output?.groundTruth ?? emptyGroundTruth());
    out.runs.push(run);
    out.costUsd = result.costUsd ?? 0;
    if (result.output) out.summary = result.output.threatModel.summary;
    else {
      out.infraFailures.push(`recon ${result.status.toLowerCase()}${result.error ? ` (${result.error})` : ''}`);
      out.deferred.push('recon failed: shards ran without ground truth');
    }
    for (const u of out.groundTruth.residualUnknowns)
      out.deferred.push(`question ${u.unknownId} [${u.kind}]: ${u.question}`);
    return out;
  }

  async map(
    subject: ShardSubject,
    source: SourceTree,
    options: { maxCostUsd: number; signal?: AbortSignal },
  ): Promise<MapOutput> {
    const { shard } = subject;
    const owned = new Set(shard.files.map((f) => f.path).filter(this.allows));
    const readable = [...owned, ...shard.neighbors.filter(this.allows)];
    const ctx = { source, paths: readable, redactions: subject.redactions };
    const context = subject.context ?? this.options.context;
    const vars = { accepted_risks: acceptedRisksVar(context) };
    const provider = this.mapProvider();
    const caps = provider.capabilities();
    const budget = contextBudgetFor(caps, DEFAULT_BUDGET);
    const pb = promptBudgetFor(budget, 'mapper');
    const slice = sliceFor(subject.groundTruth, { paths: [...owned] });
    const scannerHere = subject.scannerCandidates.filter((c) => c.locations.some((l) => owned.has(l.path)));
    const prompt = [
      `Investigate shard ${shard.shardId} (module ${shard.module}): ${shard.files.length} owned file(s), about ${shard.tokens} tokens of source.`,
      `<shard id="${shard.shardId}">\n${shard.files.map((f) => `- ${f.path} (${f.signals} signal(s), score ${f.score})`).join('\n')}\n</shard>`,
      shard.neighbors.length
        ? `Readable neighbours (context only, never report findings located in them):\n${shard.neighbors.map((n) => `- ${n}`).join('\n')}`
        : '',
      shard.signals.length
        ? `<signals>\n${shard.signals
            .slice(0, MAX_SIGNALS_IN_PROMPT)
            .map((s) => `${s.path}:${s.line ?? '?'} [${s.selectorId}] ${s.evidence}`)
            .join('\n')}\n</signals>`
        : '',
      renderGroundTruth(slice, { maxChars: pb.groundTruth }),
      subject.digest
        ? renderDigest(subject.digest, {
            path: shard.module === '(root)' ? '' : shard.module,
            depth: 1,
            maxChars: pb.digest,
          })
        : '',
      scannerHere.length
        ? `Scanner findings already recorded in these files:\n${scannerHere
            .slice(0, 40)
            .map((c) => `- ${c.category} ${c.locations[0]?.path}:${c.locations[0]?.startLine} (${c.ruleId})`)
            .join('\n')}`
        : '',
      renderOperatorContext(context),
    ]
      .filter(Boolean)
      .join('\n\n');
    const validateFull = async (r: InvestigationResult): Promise<string[]> => [
      ...(await checkCitations(
        ctx,
        r.findings.flatMap((f) => f.locations),
      )),
      ...r.findings.flatMap((f) => {
        const primary = f.locations.filter((l) => l.role === 'primary');
        if (primary.length !== 1) return [`finding "${f.title}" must have exactly one primary location`];
        const p = primary[0] as (typeof f.locations)[number];
        return owned.has(p.path)
          ? []
          : [
              `finding "${f.title}" has its primary location in ${p.path}, which this shard does not own; report it only if its primary line is in an owned file, otherwise list it under deferred as "cross-shard: ${p.path}:${p.startLine} - why"`,
            ];
      }),
      ...closedEndedProblems(r, slice),
    ];
    const lite = useLiteDeliverables(caps);
    const single = caps.toolMode === 'none' || (caps.toolMode === 'prompted' && shard.tokens <= 0.5 * budget.effective);
    const startedAt = new Date().toISOString();
    const scanId = subject.scan.scanId;
    let result: AgentRunResult<InvestigationResult | InvestigationResultLite>;
    if (single) {
      // No tools: the owned files are inlined and the reply is one JSON document (ADR-054).
      const body: string[] = [];
      for (const f of shard.files) {
        if (!owned.has(f.path)) continue;
        const text = await source.readText(f.path);
        if (text === undefined) continue;
        const lines = applyRedactions(text.split(/\r?\n/), 1, f.path, subject.redactions).map(
          (l, i) => `${String(i + 1).padStart(5)}| ${redactSecrets(l).text}`,
        );
        body.push(`<file path="${f.path}">\n${lines.join('\n')}\n</file>`);
      }
      result = await runStructured({
        provider,
        role: 'mapper',
        system: this.options.prompts.render('mapper', vars),
        prompt: `${prompt}\n\n<untrusted_repository_content>\n${body.join('\n')}\n</untrusted_repository_content>`,
        schema: InvestigationResultLite,
        validate: (r) => validateFull(liftLiteResult(r)),
        maxAttempts: 3,
        ...(this.options.effort ? { effort: this.options.effort } : {}),
        ...(options.signal ? { signal: options.signal } : {}),
        scanId,
        costOf,
        maxCostUsd: options.maxCostUsd,
      });
    } else {
      const description = 'Submit the findings of this shard. Call exactly once.';
      const submit = lite
        ? {
            name: 'submit_investigation',
            description,
            output: InvestigationResultLite,
            validate: (r: InvestigationResultLite) => validateFull(liftLiteResult(r)),
          }
        : { name: 'submit_investigation', description, output: InvestigationResult, validate: validateFull };
      const large = budget.window >= 100_000;
      result = await runAgent<InvestigationResult | InvestigationResultLite>({
        role: 'mapper',
        provider,
        tools: [
          ...createCodeTools(ctx),
          ...(subject.graph ? createGraphTools(subject.graph) : []),
          ...(subject.digest ? [createRepoMapTool(subject.digest)] : []),
        ],
        ...this.summarizer(),
        system: this.options.prompts.render('mapper', vars),
        prompt,
        submit: submit as never,
        budget: {
          maxSteps: large ? 30 : 18,
          maxToolCalls: 60,
          maxOutputTokens: 16_000,
          maxTotalTokens: 400_000,
          ...this.options.budget,
        },
        ...(this.options.effort ? { effort: this.options.effort } : {}),
        ...(options.signal ? { signal: options.signal } : {}),
        scanId,
        costOf,
        maxCostUsd: options.maxCostUsd,
      });
    }
    const run = this.record('mapper', provider, startedAt, result, scanId);
    const output = result.output
      ? lite || single
        ? liftLiteResult(result.output as InvestigationResultLite)
        : (result.output as InvestigationResult)
      : undefined;
    if (!output) {
      throw new Error(
        `shard ${shard.shardId}: mapper ${result.status.toLowerCase()}${result.error ? ` (${result.error})` : ''}`,
      );
    }
    return {
      findings: output.findings,
      invariantResults: output.invariantResults,
      variantLog: output.variantLog,
      reviewedFiles: output.reviewedFiles,
      deferred: output.deferred.map((d) => `${shard.shardId}: ${d}`),
      run,
      costUsd: result.costUsd ?? 0,
    };
  }

  async reduce(input: ReduceInput, options: { maxCostUsd: number; signal?: AbortSignal }): Promise<ReduceOutput> {
    const deferred: string[] = [];
    // 1. Deterministic: refs in a stable order, duplicates merged before any model sees them.
    const all = input.maps
      .flatMap((m) => m.findings)
      .filter((f) => f.locations.every((l) => this.allows(l.path)))
      .sort((a, b) => {
        const pa = primaryOf(a);
        const pb = primaryOf(b);
        return (
          SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
          (pa?.path ?? '').localeCompare(pb?.path ?? '') ||
          (pa?.startLine ?? 0) - (pb?.startLine ?? 0) ||
          a.title.localeCompare(b.title)
        );
      });
    type Row = { ref: string; finding: AiFinding; mergedFrom: string[] };
    const rows: Row[] = [];
    for (const f of all) {
      const dup = rows.find((r) => isDuplicate(r.finding, f) || dedupKey(r.finding) === dedupKey(f));
      if (dup) {
        if (CONFIDENCE_RANK[f.confidence] > CONFIDENCE_RANK[dup.finding.confidence]) dup.finding = f;
        dup.mergedFrom.push(f.title);
        continue;
      }
      rows.push({ ref: `F-${rows.length + 1}`, finding: f, mergedFrom: [] });
    }
    const coverage = coverageOf(input.groundTruth, input.maps);
    const finish = (
      drafts: CandidateDraft[],
      chains: AttackChain[],
      run?: AgentRunRecord,
      costUsd = 0,
    ): ReduceOutput => ({
      drafts,
      chains,
      ...(run ? { run } : {}),
      costUsd,
      deferred,
      coverage,
    });
    const deterministic = () => rows.map((r) => toDraft(r.finding, 'mapper'));
    if (rows.length === 0 || options.maxCostUsd <= 0) {
      if (rows.length && options.maxCostUsd <= 0) deferred.push('reducer skipped: cost budget exhausted');
      return finish(deterministic(), []);
    }

    // 2. The reducer sees claims only.
    const provider = this.reduceProvider();
    const table = rows.slice(0, MAX_REDUCER_ROWS).map((r) => {
      const p = primaryOf(r.finding);
      const f = r.finding;
      return [
        `${r.ref} | ${f.severity} | ${f.confidence} | ${f.category} | ${p?.path}:${p?.startLine}`,
        `  claim: ${f.claim}`,
        f.preconditions.length ? `  preconditions: ${f.preconditions.join('; ')}` : '',
        f.capabilitiesGained.length ? `  capabilities gained: ${f.capabilitiesGained.join('; ')}` : '',
        f.proofObligations.length ? `  proof obligations: ${f.proofObligations.join('; ')}` : '',
        f.invariantId || f.familyId ? `  ground truth: ${[f.invariantId, f.familyId].filter(Boolean).join(' ')}` : '',
        r.mergedFrom.length ? `  merged duplicates: ${r.mergedFrom.length}` : '',
      ]
        .filter(Boolean)
        .join('\n');
    });
    const prompt = [
      `Reduce the claims of ${input.maps.length} independent shard reviewers (${rows.length} findings after deterministic dedup).`,
      `<findings>\n${table.join('\n')}\n</findings>`,
      input.groundTruth.carveouts.length
        ? renderGroundTruth(input.groundTruth, { sections: ['carveouts', 'unknowns'] })
        : '',
      'Return a verdict row for every ref. Drop (keep=false) only with a rationale naming a carve-out id or the ref it duplicates (mergedInto).',
    ]
      .filter(Boolean)
      .join('\n\n');
    const startedAt = new Date().toISOString();
    const caps = provider.capabilities();
    const common = {
      provider,
      role: 'reducer' as const,
      system: this.options.prompts.render('reducer'),
      prompt,
      ...(this.options.effort ? { effort: this.options.effort } : {}),
      ...(options.signal ? { signal: options.signal } : {}),
      scanId: input.scan.scanId,
      costOf,
      maxCostUsd: options.maxCostUsd,
    };
    const result: AgentRunResult<ReduceResult> =
      caps.toolMode === 'none'
        ? await runStructured({ ...common, schema: ReduceResult, maxAttempts: 2 })
        : await runAgent({
            ...common,
            tools: [],
            submit: {
              name: 'submit_reduction',
              description: 'Submit verdicts, attack chains and ranking for the listed refs. Call exactly once.',
              output: ReduceResult,
              validate: (r) => reduceProblems(r, new Set(rows.map((x) => x.ref))),
            },
            budget: {
              maxSteps: 6,
              maxToolCalls: 4,
              maxOutputTokens: 16_000,
              maxTotalTokens: 200_000,
              ...this.options.budget,
            },
          });
    const run = this.record('reducer', provider, startedAt, result, input.scan.scanId);
    if (!result.output) {
      deferred.push(
        `reducer ${result.status.toLowerCase()}${result.error ? ` (${result.error})` : ''}; deterministic order kept`,
      );
      return finish(deterministic(), [], run, result.costUsd ?? 0);
    }

    // 3. Host applies the verdicts: downgrade, never delete (ADR-050).
    const byRef = new Map(rows.map((r) => [r.ref, r]));
    const verdicts = new Map(result.output.findings.map((v) => [v.ref, v]));
    const kept: Row[] = [];
    for (const row of rows) {
      const v = verdicts.get(row.ref);
      if (!v) {
        kept.push(row);
        continue;
      }
      const f = { ...row.finding };
      const upOne = SEVERITY_RANK[v.severity] <= SEVERITY_RANK[f.severity] + 1;
      if (upOne) f.severity = v.severity;
      else
        deferred.push(`${row.ref}: reducer raised severity to ${v.severity} by more than one tier; kept ${f.severity}`);
      f.confidence = v.confidence;
      if (!v.keep) {
        const justified =
          /\bCO-\d+\b/.test(v.rationale) || (v.mergedInto && byRef.has(v.mergedInto) && v.mergedInto !== row.ref);
        if (justified) {
          deferred.push(`${row.ref} dropped by reducer: ${v.rationale.slice(0, 200)}`);
          continue;
        }
        f.confidence = 'LOW';
        deferred.push(
          `${row.ref}: reducer wanted to drop it without a carve-out or duplicate; kept with LOW confidence`,
        );
      }
      kept.push({ ...row, finding: f });
    }
    const order = new Map(result.output.ranking.map((ref, i) => [ref, i]));
    kept.sort(
      (a, b) =>
        (order.get(a.ref) ?? Number.MAX_SAFE_INTEGER) - (order.get(b.ref) ?? Number.MAX_SAFE_INTEGER) ||
        SEVERITY_RANK[b.finding.severity] - SEVERITY_RANK[a.finding.severity],
    );
    const keptRefs = new Set(kept.map((k) => k.ref));
    const chains = result.output.chains.filter((c) => c.members.every((m) => keptRefs.has(m)));
    const drafts = kept.map((k) => {
      const draft = toDraft(k.finding, 'mapper');
      const inChains = chains.filter((c) => c.members.includes(k.ref));
      if (inChains.length)
        draft.message += `\n${inChains.map((c) => `Attack chain ${c.chainId} (${c.combinedSeverity}): ${c.narrative}`).join('\n')}`;
      return draft;
    });
    return finish(drafts, chains, run, result.costUsd ?? 0);
  }
}

function primaryOf(f: AiFinding) {
  return f.locations.find((l) => l.role === 'primary') ?? f.locations[0];
}

/** Agent Code's dedup key: first CWE, path, 5-line bucket, first 40 title characters. */
export function dedupKey(f: AiFinding): string {
  const p = primaryOf(f);
  return `${f.cwe[0] ?? ''}|${p?.path ?? ''}|${Math.floor((p?.startLine ?? 0) / 5)}|${f.title.toLowerCase().slice(0, 40)}`;
}

/** Problems returned to the reducer: unknown refs, self-merges, cyclic merges, broken chains. */
export function reduceProblems(r: ReduceResult, refs: ReadonlySet<string>): string[] {
  const problems: string[] = [];
  const merged = new Map<string, string>();
  for (const v of r.findings) {
    if (!refs.has(v.ref)) problems.push(`${v.ref} is not a listed finding`);
    if (v.mergedInto) {
      if (!refs.has(v.mergedInto)) problems.push(`${v.ref}: mergedInto ${v.mergedInto} is not a listed finding`);
      if (v.mergedInto === v.ref) problems.push(`${v.ref} cannot merge into itself`);
      merged.set(v.ref, v.mergedInto);
    }
  }
  for (const [from, to] of merged)
    if (merged.get(to) === from) problems.push(`${from} and ${to} merge into each other`);
  for (const c of r.chains) {
    if (new Set(c.members).size !== c.members.length) problems.push(`${c.chainId} lists a member twice`);
    for (const m of c.members) if (!refs.has(m)) problems.push(`${c.chainId}: member ${m} is not a listed finding`);
  }
  for (const ref of r.ranking) if (!refs.has(ref)) problems.push(`ranking names unknown ref ${ref}`);
  return problems;
}

/** Severity helper for reports: the most severe tier of a set. */
export function maxSeverity(values: readonly Severity[]): Severity | undefined {
  return [...values].sort((a, b) => SEVERITY_RANK[b] - SEVERITY_RANK[a])[0];
}
