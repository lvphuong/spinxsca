import type { ExplainOutcome, ExplainSubject, FindingExplainer, SourceTree } from '@spinxsca/core';
import { newId } from '@spinxsca/core';
import { type AgentRunRecord, AiExplanation, type Digest } from '@spinxsca/schemas';
import { costOf } from '../llm/pricing';
import type { Effort, LlmProvider } from '../llm/types';
import type { PromptBundle } from '../prompts/bundle';
import { type AgentBudget, type AgentRunResult, runAgent } from '../runtime/loop';
import { checkCitations, createCodeTools } from '../tools/code-tools';

export const EXPLAIN_POLICY_VERSION = 'explain-v1';

export interface AgentExplainerOptions {
  /** A fresh provider per run (scripted providers hold per-run state). */
  provider: () => LlmProvider;
  prompts: PromptBundle;
  effort?: Effort;
  budget?: Partial<AgentBudget>;
  maxCostUsdPerFinding?: number;
}

/** Validator-lite + risk assessor role (docs/architecture/03 sections 2 and 9). */
export class AgentExplainer implements FindingExplainer {
  readonly info: FindingExplainer['info'];

  constructor(private readonly options: AgentExplainerOptions) {
    const provider = options.provider();
    this.info = {
      provider: provider.id,
      model: provider.model,
      promptBundleDigest: options.prompts.digest,
      policyVersion: EXPLAIN_POLICY_VERSION,
    };
  }

  async explain(subject: ExplainSubject, source: SourceTree, signal?: AbortSignal): Promise<ExplainOutcome> {
    const startedAt = new Date().toISOString();
    const ctx = { source, paths: subject.snapshotPaths, redactions: subject.redactions, findings: subject.related };
    const provider = this.options.provider();
    const result = await runAgent({
      role: 'explain',
      provider,
      system: this.options.prompts.render('explain'),
      prompt: explainPrompt(subject),
      tools: createCodeTools(ctx),
      submit: {
        name: 'submit_explanation',
        description: 'Submit the validated explanation of the finding. Call exactly once when done.',
        output: AiExplanation,
        validate: (output) => checkCitations(ctx, output.evidence),
      },
      budget: {
        maxSteps: 16,
        maxToolCalls: 40,
        maxOutputTokens: 32_000,
        maxTotalTokens: 400_000,
        ...this.options.budget,
      },
      ...(this.options.effort ? { effort: this.options.effort } : {}),
      ...(signal ? { signal } : {}),
      scanId: subject.scan.scanId,
      costOf,
      ...(this.options.maxCostUsdPerFinding ? { maxCostUsd: this.options.maxCostUsdPerFinding } : {}),
    });
    return {
      ...(result.output ? { explanation: result.output } : {}),
      run: toRecord(result, {
        role: 'explain',
        provider,
        promptBundleDigest: this.options.prompts.digest,
        startedAt,
        scanId: subject.scan.scanId,
        findingId: subject.finding.findingId,
        subjectDigest: subject.occurrence.fingerprint,
      }),
    };
  }
}

export function toRecord(
  result: AgentRunResult<unknown>,
  meta: {
    role: AgentRunRecord['role'];
    provider: LlmProvider;
    promptBundleDigest: Digest;
    startedAt: string;
    scanId?: string;
    findingId?: string;
    subjectDigest?: string;
  },
): AgentRunRecord {
  return {
    agentRunId: newId('run'),
    role: meta.role,
    ...(meta.scanId ? { scanId: meta.scanId } : {}),
    ...(meta.findingId ? { findingId: meta.findingId } : {}),
    ...(meta.subjectDigest ? { subjectDigest: meta.subjectDigest } : {}),
    provider: meta.provider.id,
    model: meta.provider.model,
    modelsUsed: result.models,
    promptBundleDigest: meta.promptBundleDigest,
    status: result.status,
    usage: result.usage,
    ...(result.costUsd !== undefined ? { costUsd: result.costUsd } : {}),
    ...(result.output !== undefined ? { output: result.output } : {}),
    ...(result.error ? { error: result.error } : {}),
    ...(result.refusal?.category ? { refusalCategory: result.refusal.category } : {}),
    steps: result.steps.map((s) => ({
      index: s.index,
      stopReason: s.stopReason,
      model: s.model,
      toolCalls: s.toolCalls,
    })),
    startedAt: meta.startedAt,
    completedAt: new Date().toISOString(),
  };
}

/** The finding as structured context; repository excerpts are marked untrusted. */
export function explainPrompt(subject: ExplainSubject): string {
  const candidate = subject.candidates[0];
  const context = {
    findingId: subject.finding.findingId,
    title: subject.finding.title,
    category: subject.finding.category,
    cwe: subject.finding.cwe,
    ruleIds: subject.occurrence.ruleIds,
    scannerSeverity: candidate?.severityHint,
    locations: subject.occurrence.locations.map((l) => ({
      path: l.path,
      startLine: l.startLine,
      endLine: l.endLine,
      role: l.role,
    })),
  };
  const excerpts = subject.evidence
    .filter((e) => e.excerpt)
    .map((e) => `<untrusted_repository_content summary="${e.summary}">\n${e.excerpt}\n</untrusted_repository_content>`)
    .join('\n\n');
  return [
    'Validate and explain this static analysis finding.',
    '',
    '<finding_context>',
    JSON.stringify(context, null, 2),
    '</finding_context>',
    '',
    `Scanner message (untrusted): ${candidate?.message ?? 'n/a'}`,
    '',
    excerpts,
    '',
    subject.related.length
      ? `Other findings in this scan: ${subject.related.length} (use list_findings).`
      : 'No other findings in this scan.',
  ].join('\n');
}
