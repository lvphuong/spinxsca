import type {
  CandidateDraft,
  InvestigationOutcome,
  InvestigationSubject,
  Investigator,
  SourceTree,
} from '@spinxsca/core';
import {
  type AgentRunRecord,
  type AiFinding,
  InvestigationResult,
  type Location,
  ThreatModel,
} from '@spinxsca/schemas';
import { costOf } from '../llm/pricing';
import type { Effort, LlmProvider } from '../llm/types';
import type { PromptBundle } from '../prompts/bundle';
import { type AgentBudget, runAgent } from '../runtime/loop';
import { checkCitations, createCodeTools } from '../tools/code-tools';
import { createGraphTools } from '../tools/graph-tools';
import { EXPLAIN_POLICY_VERSION, toRecord } from './explainer';

export interface AgentInvestigatorOptions {
  provider: () => LlmProvider;
  prompts: PromptBundle;
  effort?: Effort;
  budget?: Partial<AgentBudget>;
  /** Investigators run concurrently up to this limit. */
  concurrency?: number;
  maxPackets?: number;
}

/**
 * Standard-level investigation (ADR-024): a planner builds a threat model with packets, investigators
 * work each packet, and an independent auditor runs without the threat model. Findings come back as
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
      policyVersion: `${EXPLAIN_POLICY_VERSION}+investigate-v1`,
    };
  }

  async investigate(
    subject: InvestigationSubject,
    source: SourceTree,
    options: { maxCostUsd: number; signal?: AbortSignal },
  ): Promise<InvestigationOutcome> {
    const runs: AgentRunRecord[] = [];
    const drafts: CandidateDraft[] = [];
    const deferred: string[] = [];
    let cost = 0;
    const ctx = { source, paths: subject.snapshotPaths, redactions: subject.redactions };
    const tools = [...createCodeTools(ctx), ...(subject.graph ? createGraphTools(subject.graph) : [])];
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
    const validateFindings = async (result: { findings: AiFinding[] }) => [
      ...(await checkCitations(
        ctx,
        result.findings.flatMap((f) => f.locations),
      )),
      ...result.findings
        .filter((f) => f.locations.filter((l) => l.role === 'primary').length !== 1)
        .map((f) => `finding "${f.title}" must have exactly one primary location`),
    ];

    // Planner.
    const startedAt = new Date().toISOString();
    const planner = this.options.provider();
    const plan = await runAgent({
      ...common,
      role: 'planner',
      provider: planner,
      system: this.options.prompts.render('planner'),
      prompt: `Build the threat model and investigation packets for this codebase.\n\nFiles: ${subject.snapshotPaths.length}. Endpoints discovered: ${subject.graph?.endpoints().length ?? 'unknown (no index)'}.\n\nScanner findings already recorded:\n${scannerSummary}${focus}`,
      submit: {
        name: 'submit_threat_model',
        description: 'Submit the threat model and packets. Call exactly once.',
        output: ThreatModel,
        validate: (tm) =>
          checkCitations(
            ctx,
            tm.packets.flatMap((p) => p.entryPoints.map((e) => ({ path: e.path, startLine: e.line, endLine: e.line }))),
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
    runs.push(
      toRecord(plan, {
        role: 'planner',
        provider: planner,
        promptBundleDigest: this.options.prompts.digest,
        startedAt,
        scanId: subject.scan.scanId,
      }),
    );
    cost += plan.costUsd ?? 0;
    const packets = plan.output?.packets.slice(0, this.options.maxPackets ?? 6) ?? [];
    if (!plan.output) deferred.push(`planner ${plan.status.toLowerCase()}${plan.error ? ` (${plan.error})` : ''}`);

    type RoleOutcome = { run?: AgentRunRecord; drafts: CandidateDraft[]; deferred: string[] };
    const runRole = async (role: 'investigator' | 'auditor', prompt: string, label: string): Promise<RoleOutcome> => {
      if (remaining() <= 0) return { drafts: [], deferred: [`${label}: cost budget exhausted`] };
      const provider = this.options.provider();
      const started = new Date().toISOString();
      const result = await runAgent({
        ...common,
        role,
        provider,
        system: this.options.prompts.render(role),
        prompt,
        submit: {
          name: 'submit_investigation',
          description: 'Submit the findings of this investigation. Call exactly once.',
          output: InvestigationResult,
          validate: validateFindings,
        },
        budget: {
          maxSteps: 30,
          maxToolCalls: 80,
          maxOutputTokens: 32_000,
          maxTotalTokens: 800_000,
          ...this.options.budget,
        },
        maxCostUsd: remaining(),
      });
      cost += result.costUsd ?? 0;
      const run = toRecord(result, {
        role,
        provider,
        promptBundleDigest: this.options.prompts.digest,
        startedAt: started,
        scanId: subject.scan.scanId,
      });
      if (!result.output) {
        return {
          run,
          drafts: [],
          deferred: [`${label}: ${result.status.toLowerCase()}${result.error ? ` (${result.error})` : ''}`],
        };
      }
      return {
        run,
        drafts: result.output.findings.map((f) => toDraft(f, role)),
        deferred: result.output.deferred.map((d) => `${label}: ${d}`),
      };
    };

    const investigations = packets.map(
      (packet) => () =>
        runRole(
          'investigator',
          `Investigate this packet.\n\n<packet>\n${JSON.stringify(packet, null, 2)}\n</packet>\n\nThreat model summary (untrusted, written by another reviewer):\n${plan.output?.summary ?? ''}\n\nScanner findings already recorded:\n${scannerSummary}${focus}`,
          `packet ${packet.packetId}`,
        ),
    );
    investigations.push(() =>
      runRole(
        'auditor',
        `Audit this codebase independently.\n\nFiles: ${subject.snapshotPaths.length}.\n\nScanner findings already recorded:\n${scannerSummary}${focus}`,
        'auditor',
      ),
    );
    // Roles run concurrently; results are recorded in packet order so runs are deterministic.
    const outcomes = await runLimited(investigations, this.options.concurrency ?? 2);
    for (const outcome of outcomes) {
      if (outcome.run) runs.push(outcome.run);
      drafts.push(...outcome.drafts);
      deferred.push(...outcome.deferred);
    }
    return { drafts, runs, costUsd: cost, deferred };
  }
}

function toDraft(finding: AiFinding, role: 'investigator' | 'auditor'): CandidateDraft {
  const locations: Location[] = finding.locations.map((l) => ({
    path: l.path,
    startLine: l.startLine,
    endLine: Math.max(l.endLine, l.startLine),
    role: l.role,
  }));
  return {
    scanner: 'ai',
    ruleId: `ai.${role}.${finding.category.toLowerCase()}`,
    ruleFamily: finding.category.toLowerCase(),
    category: finding.category,
    cwe: finding.cwe,
    title: finding.title,
    message: `${finding.summary} Invariant violated: ${finding.invariantViolated}. Attacker: ${finding.attacker}. Evidence: ${finding.evidence.join(' ')}${finding.counterevidence.length ? ` Counterevidence considered: ${finding.counterevidence.join(' ')}` : ''} Remediation: ${finding.remediation}`,
    severityHint: finding.severity,
    confidenceHint: finding.confidence,
    locations,
  };
}

async function runLimited<T>(tasks: Array<() => Promise<T>>, limit: number): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let next = 0;
  const worker = async () => {
    while (next < tasks.length) {
      const index = next++;
      results[index] = await (tasks[index] as () => Promise<T>)();
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker));
  return results;
}
