import {
  buildResourceMatrix,
  type CandidateDraft,
  type InvestigationOutcome,
  type InvestigationSubject,
  type Investigator,
  type ResourceMatrix,
  renderCensus,
  renderGroup,
  type SourceTree,
} from '@spinxsca/core';
import {
  type AgentRunRecord,
  type AiContextConfig,
  type AiFinding,
  type GroundTruth,
  type InvestigationPacket,
  InvestigationResult,
  type Location,
  ReconDeliverable,
  ThreatModel,
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
import type { PromptBundle } from '../prompts/bundle';
import { runLimited } from '../runtime/concurrency';
import { type AgentBudget, runAgent } from '../runtime/loop';
import { createCensusTools } from '../tools/census-tools';
import { checkCitations, createCodeTools } from '../tools/code-tools';
import { createGraphTools } from '../tools/graph-tools';
import { EXPLAIN_POLICY_VERSION, toRecord } from './explainer';

export interface ReconOptions {
  /** Recon-first flow (ADR-049); false restores the planner-only flow. */
  enabled?: boolean;
  /** Completeness re-passes per packet (0 disables the critic). */
  criticPasses?: number;
  /** Inject the deterministic census worksheet and tools. */
  census?: boolean;
  /** Deep level only: upper bound of LOGIC_AUDIT items seeded per case. */
  maxLogicItems?: number;
}

export interface AgentInvestigatorOptions {
  provider: () => LlmProvider;
  prompts: PromptBundle;
  effort?: Effort;
  budget?: Partial<AgentBudget>;
  /** Investigators run concurrently up to this limit. */
  concurrency?: number;
  maxPackets?: number;
  recon?: ReconOptions;
  /** Operator context pack (ADR-051); the subject's context wins when both are set. */
  context?: AiContextConfig;
}

type Role = 'investigator' | 'auditor' | 'critic';
type RoleOutcome = {
  run?: AgentRunRecord;
  output?: InvestigationResult;
  drafts: CandidateDraft[];
  deferred: string[];
  infra: string[];
};

const CRITIC_CONTEXT_CAP = 12_000;

/**
 * Standard-level investigation (ADR-024, ADR-049): one recon run classifies the target, writes the
 * threat model and extracts ground truth (invariants, baseline-correct references, variant
 * families, carve-outs); investigators work each packet against its slice of that ground truth and
 * must account for every invariant and family member; a critic re-pass per packet looks only for
 * what was missed; an independent auditor runs blind to the threat model. Findings come back as
 * candidate drafts so the host assigns identity and reconciles them with scanner output.
 */
export class AgentInvestigator implements Investigator {
  readonly info: Investigator['info'];

  constructor(private readonly options: AgentInvestigatorOptions) {
    const provider = options.provider();
    this.info = {
      provider: provider.id,
      model: provider.model,
      promptBundleDigest: options.prompts.digest,
      policyVersion: `${EXPLAIN_POLICY_VERSION}+investigate-v2`,
    };
  }

  async investigate(
    subject: InvestigationSubject,
    source: SourceTree,
    options: { maxCostUsd: number; signal?: AbortSignal; onRun?: (run: AgentRunRecord) => Promise<void> },
  ): Promise<InvestigationOutcome> {
    const recon = { enabled: true, criticPasses: 1, census: true, ...this.options.recon };
    const context = subject.context ?? this.options.context;
    const vars = { accepted_risks: acceptedRisksVar(context) };
    const runs: AgentRunRecord[] = [];
    const deferred: string[] = [];
    const infraFailures: string[] = [];
    let cost = 0;
    const ctx = { source, paths: subject.snapshotPaths, redactions: subject.redactions };
    const matrix: ResourceMatrix | undefined =
      subject.graph && recon.census
        ? await buildResourceMatrix(subject.graph, source, subject.snapshotPaths)
        : undefined;
    const tools = [
      ...createCodeTools(ctx),
      ...(subject.graph ? createGraphTools(subject.graph) : []),
      ...(matrix ? createCensusTools(matrix) : []),
    ];
    const remaining = () => Math.max(0, options.maxCostUsd - cost);
    const common = {
      tools,
      ...(this.options.effort ? { effort: this.options.effort } : {}),
      ...(options.signal ? { signal: options.signal } : {}),
      scanId: subject.scan.scanId,
      costOf,
    };
    const scannerSummary = subject.scannerCandidates.length
      ? subject.scannerCandidates
          .slice(0, 60)
          .map((c) => `- ${c.category} ${c.locations[0]?.path}:${c.locations[0]?.startLine} (${c.ruleId})`)
          .join('\n')
      : '(none)';
    const focus = subject.focus
      ? `\nThis is an incremental review. Focus on these changed or affected files:\n${subject.focus.files
          .slice(0, 40)
          .map((f) => `- ${f}`)
          .join(
            '\n',
          )}${subject.focus.endpointIds.length ? `\nAffected endpoints: ${subject.focus.endpointIds.join(', ')}` : ''}`
      : '';
    const operatorContext = renderOperatorContext(context);
    const census = matrix ? renderCensus(matrix) : '';
    const censusJsonBlock = matrix ? `\n<census_json>\n${censusJsonOf(matrix)}\n</census_json>` : '';
    const stats = `Files: ${subject.snapshotPaths.length}. Endpoints discovered: ${subject.graph?.endpoints().length ?? 'unknown (no index)'}.`;

    const record = async <O>(
      role: AgentRunRecord['role'],
      provider: LlmProvider,
      startedAt: string,
      result: Awaited<ReturnType<typeof runAgent<O>>>,
    ) => {
      cost += result.costUsd ?? 0;
      const run = toRecord(result, {
        role,
        provider,
        promptBundleDigest: this.options.prompts.digest,
        startedAt,
        scanId: subject.scan.scanId,
      });
      // Persisted as soon as it finishes (a crash keeps the audit trail); `runs` is filled in
      // deterministic order (recon, investigators by packet, auditor, critics) once a wave completes.
      await options.onRun?.(run);
      return run;
    };

    // 1. Recon (or the legacy planner): threat model, packets and ground truth.
    let packets: InvestigationPacket[] = [];
    let summary = '';
    let groundTruth = emptyGroundTruth();
    if (recon.enabled) {
      const provider = this.options.provider();
      const startedAt = new Date().toISOString();
      const result = await runAgent({
        ...common,
        role: 'recon',
        provider,
        system: this.options.prompts.render('recon', vars),
        prompt: [
          'Reconnoitre this codebase: classify it, build the threat model and packets, and extract the ground truth.',
          '',
          stats,
          '',
          `Scanner findings already recorded:\n${scannerSummary}${focus}`,
          operatorContext,
          census,
          censusJsonBlock,
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
        maxCostUsd: remaining(),
      });
      runs.push(await record('recon', provider, startedAt, result));
      if (result.output) {
        packets = result.output.threatModel.packets.slice(0, this.options.maxPackets ?? 6);
        summary = result.output.threatModel.summary;
        groundTruth = result.output.groundTruth;
      } else {
        infraFailures.push(`recon ${result.status.toLowerCase()}${result.error ? ` (${result.error})` : ''}`);
        deferred.push('recon failed: investigators ran without ground truth');
      }
    } else {
      const provider = this.options.provider();
      const startedAt = new Date().toISOString();
      const plan = await runAgent({
        ...common,
        role: 'planner',
        provider,
        system: this.options.prompts.render('planner', vars),
        prompt: `Build the threat model and investigation packets for this codebase.\n\n${stats}\n\nScanner findings already recorded:\n${scannerSummary}${focus}`,
        submit: {
          name: 'submit_threat_model',
          description: 'Submit the threat model and packets. Call exactly once.',
          output: ThreatModel,
          validate: (tm) =>
            checkCitations(
              ctx,
              tm.packets.flatMap((p) =>
                p.entryPoints.map((e) => ({ path: e.path, startLine: e.line, endLine: e.line })),
              ),
            ),
        },
        budget: {
          maxSteps: 24,
          maxToolCalls: 60,
          maxOutputTokens: 32_000,
          maxTotalTokens: 600_000,
          ...this.options.budget,
        },
        maxCostUsd: remaining(),
      });
      runs.push(await record('planner', provider, startedAt, plan));
      packets = plan.output?.packets.slice(0, this.options.maxPackets ?? 6) ?? [];
      summary = plan.output?.summary ?? '';
      if (!plan.output)
        infraFailures.push(`planner ${plan.status.toLowerCase()}${plan.error ? ` (${plan.error})` : ''}`);
    }
    groundTruth = mergeOperatorContext(groundTruth, context);
    for (const u of groundTruth.residualUnknowns) deferred.push(`question ${u.unknownId} [${u.kind}]: ${u.question}`);

    const slices = new Map(
      packets.map((p) => [
        p.packetId,
        sliceFor(groundTruth, { packetIds: [p.packetId], paths: p.entryPoints.map((e) => e.path) }),
      ]),
    );
    const censusFor = (paths: readonly string[]): string => {
      if (!matrix) return '';
      const set = new Set(paths);
      const groups = matrix.groups.filter((g) => g.rows.some((r) => set.has(r.path)));
      return groups.length
        ? `Census rows for your entry points (heuristic evidence, not findings):\n${groups.map(renderGroup).join('\n\n')}`.slice(
            0,
            3000,
          )
        : '';
    };

    const runRole = async (
      role: Role,
      prompt: string,
      label: string,
      slice: GroundTruth | undefined,
    ): Promise<RoleOutcome> => {
      if (remaining() <= 0) return { drafts: [], deferred: [`${label}: cost budget exhausted`], infra: [] };
      const provider = this.options.provider();
      const started = new Date().toISOString();
      const result = await runAgent({
        ...common,
        role,
        provider,
        system: this.options.prompts.render(role, vars),
        prompt,
        submit: {
          name: 'submit_investigation',
          description: 'Submit the findings of this investigation. Call exactly once.',
          output: InvestigationResult,
          validate: async (r) => [
            ...(await checkCitations(
              ctx,
              r.findings.flatMap((f) => f.locations),
            )),
            ...r.findings
              .filter((f) => f.locations.filter((l) => l.role === 'primary').length !== 1)
              .map((f) => `finding "${f.title}" must have exactly one primary location`),
            ...(slice ? closedEndedProblems(r, slice) : []),
          ],
        },
        budget: {
          maxSteps: role === 'critic' ? 20 : 30,
          maxToolCalls: role === 'critic' ? 50 : 80,
          maxOutputTokens: 32_000,
          maxTotalTokens: 800_000,
          ...this.options.budget,
        },
        maxCostUsd: remaining(),
      });
      const run = await record(role, provider, started, result);
      if (!result.output) {
        return {
          run,
          drafts: [],
          deferred: [],
          infra: [`${label}: ${result.status.toLowerCase()}${result.error ? ` (${result.error})` : ''}`],
        };
      }
      return {
        run,
        output: result.output,
        drafts: result.output.findings.map((f) => toDraft(f, role)),
        deferred: result.output.deferred.map((d) => `${label}: ${d}`),
        infra: [],
      };
    };

    const packetPrompt = (packet: InvestigationPacket) =>
      [
        `Investigate this packet.\n\n<packet>\n${JSON.stringify(packet, null, 2)}\n</packet>`,
        `Threat model summary (untrusted, written by another reviewer):\n${summary}`,
        renderGroundTruth(slices.get(packet.packetId) ?? groundTruth),
        censusFor(packet.entryPoints.map((e) => e.path)),
        operatorContext,
        `Scanner findings already recorded:\n${scannerSummary}${focus}`,
      ]
        .filter(Boolean)
        .join('\n\n');

    // 2. Investigators (one per packet) and the blind auditor run concurrently.
    const wave = packets.map(
      (packet) => () =>
        runRole('investigator', packetPrompt(packet), `packet ${packet.packetId}`, slices.get(packet.packetId)),
    );
    wave.push(() =>
      runRole(
        'auditor',
        [
          `Audit this codebase independently.\n\n${stats}`,
          groundTruth.carveouts.length ? renderGroundTruth(groundTruth, { sections: ['carveouts'] }) : '',
          operatorContext,
          `Scanner findings already recorded:\n${scannerSummary}${focus}`,
        ]
          .filter(Boolean)
          .join('\n\n'),
        'auditor',
        undefined,
      ),
    );
    const outcomes = await runLimited(wave, this.options.concurrency ?? 2);
    for (const o of outcomes) if (o.run) runs.push(o.run);
    const results: InvestigationResult[] = [];
    const draftsByPacket = new Map<string, CandidateDraft[]>();
    const findingsByPacket = new Map<string, AiFinding[]>();
    const allDrafts: CandidateDraft[] = [];
    const accept = (packetId: string | undefined, o: RoleOutcome) => {
      deferred.push(...o.deferred);
      infraFailures.push(...o.infra);
      if (o.output) results.push(o.output);
      const fresh = o.output?.findings ?? [];
      if (packetId) {
        findingsByPacket.set(packetId, [...(findingsByPacket.get(packetId) ?? []), ...fresh]);
        draftsByPacket.set(packetId, [...(draftsByPacket.get(packetId) ?? []), ...o.drafts]);
      }
      allDrafts.push(...o.drafts);
    };
    for (const [i, o] of outcomes.entries()) accept(packets[i]?.packetId, o);

    // 3. Critic re-passes: only what the first pass missed, until a pass adds nothing.
    if (recon.enabled && recon.criticPasses > 0) {
      const criticRuns = new Map<string, AgentRunRecord[]>();
      const criticFor = (packet: InvestigationPacket) => async (): Promise<void> => {
        for (let pass = 1; pass <= recon.criticPasses; pass++) {
          const known = findingsByPacket.get(packet.packetId) ?? [];
          const reported = known.length
            ? known
                .map((f) => {
                  const p = f.locations.find((l) => l.role === 'primary') ?? f.locations[0];
                  return `- ${f.title} (${p?.path}:${p?.startLine})`;
                })
                .join('\n')
            : '(none)';
          const prior = results
            .filter((r) => r.findings.some((f) => known.includes(f)) || known.length === 0)
            .slice(-1)[0];
          const log = prior
            ? JSON.stringify({ invariantResults: prior.invariantResults, variantLog: prior.variantLog }).slice(
                0,
                CRITIC_CONTEXT_CAP,
              )
            : '{}';
          const o = await runRole(
            'critic',
            [
              `Completeness re-pass ${pass} over this packet.\n\n<packet>\n${JSON.stringify(packet, null, 2)}\n</packet>`,
              renderGroundTruth(slices.get(packet.packetId) ?? groundTruth),
              `Already reported for this packet (do NOT repeat):\n${reported}`,
              `Checklist and hunt log produced so far:\n${log}`,
              censusFor(packet.entryPoints.map((e) => e.path)),
              operatorContext,
            ]
              .filter(Boolean)
              .join('\n\n'),
            `critic ${packet.packetId} pass ${pass}`,
            slices.get(packet.packetId),
          );
          if (o.run) criticRuns.set(packet.packetId, [...(criticRuns.get(packet.packetId) ?? []), o.run]);
          const fresh = (o.output?.findings ?? []).filter((f) => !known.some((k) => isDuplicate(k, f)));
          const freshDrafts = fresh.map((f) => toDraft(f, 'critic'));
          accept(packet.packetId, {
            ...o,
            drafts: freshDrafts,
            output: o.output ? { ...o.output, findings: fresh } : undefined,
          });
          if (fresh.length === 0) break;
        }
      };
      await runLimited(packets.map(criticFor), this.options.concurrency ?? 2);
      for (const packet of packets) runs.push(...(criticRuns.get(packet.packetId) ?? []));
    }

    // 4. Dedupe across roles (same category, overlapping primary lines): the first report wins.
    const drafts: CandidateDraft[] = [];
    const seen: AiFinding[] = [];
    for (const d of allDrafts) {
      const probe: Pick<AiFinding, 'title' | 'category' | 'locations'> = {
        title: d.title,
        category: d.category,
        locations: d.locations.map((l) => ({ ...l, role: (l.role ?? 'primary') as 'primary' })),
      };
      if (seen.some((s) => isDuplicate(s, probe))) continue;
      seen.push(probe as AiFinding);
      drafts.push(d);
    }
    return {
      drafts,
      runs,
      costUsd: cost,
      deferred,
      infraFailures,
      groundTruth,
      coverage: coverageOf(groundTruth, results),
    };
  }
}

function censusJsonOf(matrix: ResourceMatrix): string {
  return JSON.stringify({
    groups: matrix.groups.map((g) => ({
      group: g.group,
      rows: g.rows.map((r) => ({
        method: r.method,
        route: r.route,
        path: r.path,
        line: r.line,
        handler: r.handler,
        flagged: r.flagged,
        scoped: r.dataAccess.map((d) => d.scopedBy),
      })),
    })),
  });
}

function toDraft(finding: AiFinding, role: Role): CandidateDraft {
  const locations: Location[] = finding.locations.map((l) => ({
    path: l.path,
    startLine: l.startLine,
    endLine: Math.max(l.endLine, l.startLine),
    role: l.role,
  }));
  const claim = {
    claim: finding.claim,
    preconditions: finding.preconditions,
    capabilitiesGained: finding.capabilitiesGained,
    proofObligations: finding.proofObligations,
    threatModelClass: finding.threatModelClass,
    ...(finding.baselineReference ? { baselineReference: finding.baselineReference } : {}),
    ...(finding.invariantId ? { invariantId: finding.invariantId } : {}),
    ...(finding.familyId ? { familyId: finding.familyId } : {}),
    ...(finding.sourcePass ? { sourcePass: finding.sourcePass } : {}),
  };
  const contract = [
    `Claim: ${finding.claim}`,
    finding.preconditions.length ? `Preconditions: ${finding.preconditions.join('; ')}` : '',
    finding.capabilitiesGained.length ? `Capabilities gained: ${finding.capabilitiesGained.join('; ')}` : '',
    finding.proofObligations.length ? `Proof obligations: ${finding.proofObligations.join('; ')}` : '',
    `Class: ${finding.threatModelClass}`,
  ]
    .filter(Boolean)
    .join(' ');
  return {
    scanner: 'ai',
    ruleId: `ai.${role}.${finding.category.toLowerCase()}`,
    ruleFamily: finding.category.toLowerCase(),
    category: finding.category,
    cwe: finding.cwe,
    title: finding.title,
    message: `${finding.summary} Invariant violated: ${finding.invariantViolated}. Attacker: ${finding.attacker}. ${contract} Evidence: ${finding.evidence.join(' ')}${finding.counterevidence.length ? ` Counterevidence considered: ${finding.counterevidence.join(' ')}` : ''} Remediation: ${finding.remediation}`,
    severityHint: finding.severity,
    confidenceHint: finding.confidence,
    locations,
    claim,
  };
}
