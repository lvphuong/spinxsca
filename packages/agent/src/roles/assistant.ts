import type { AskSubject, ProjectAssistant, SourceTree } from '@spinxsca/core';
import { type AgentRunRecord, AiAnswer } from '@spinxsca/schemas';
import { costOf } from '../llm/pricing';
import type { Effort, LlmProvider } from '../llm/types';
import type { PromptBundle } from '../prompts/bundle';
import { runAgent } from '../runtime/loop';
import { checkCitations, createCodeTools } from '../tools/code-tools';
import { EXPLAIN_POLICY_VERSION, explainPrompt, toRecord } from './explainer';

/** Developer assistant answering free-form questions about the scanned code (docs/architecture/03 section 12). */
export class AgentAssistant implements ProjectAssistant {
  readonly info: ProjectAssistant['info'];

  constructor(
    private readonly options: {
      provider: () => LlmProvider;
      prompts: PromptBundle;
      effort?: Effort;
      maxCostUsd?: number;
    },
  ) {
    const provider = options.provider();
    this.info = {
      provider: provider.id,
      model: provider.model,
      promptBundleDigest: options.prompts.digest,
      policyVersion: EXPLAIN_POLICY_VERSION,
    };
  }

  async ask(
    subject: AskSubject,
    source: SourceTree,
    signal?: AbortSignal,
  ): Promise<{ answer?: AiAnswer; run: AgentRunRecord }> {
    const startedAt = new Date().toISOString();
    const ctx = { source, paths: subject.snapshotPaths, redactions: subject.redactions, findings: subject.findings };
    const provider = this.options.provider();
    const prompt = [
      `Question: ${subject.question}`,
      '',
      subject.focus ? `The question is about this finding:\n${explainPrompt(subject.focus)}` : '',
      subject.findings.length
        ? `The latest scan recorded ${subject.findings.length} findings (use list_findings).`
        : 'No findings are recorded.',
    ]
      .filter(Boolean)
      .join('\n');
    const result = await runAgent({
      role: 'ask',
      provider,
      system: this.options.prompts.render('ask'),
      prompt,
      tools: createCodeTools(ctx),
      submit: {
        name: 'submit_answer',
        description: 'Submit the answer with citations. Call exactly once when done.',
        output: AiAnswer,
        validate: (output) => checkCitations(ctx, output.citations),
      },
      budget: { maxSteps: 20, maxToolCalls: 50, maxOutputTokens: 32_000, maxTotalTokens: 500_000 },
      ...(this.options.effort ? { effort: this.options.effort } : {}),
      ...(signal ? { signal } : {}),
      costOf,
      ...(this.options.maxCostUsd ? { maxCostUsd: this.options.maxCostUsd } : {}),
    });
    return {
      ...(result.output ? { answer: result.output } : {}),
      run: toRecord(result, {
        role: 'ask',
        provider,
        promptBundleDigest: this.options.prompts.digest,
        startedAt,
        ...(subject.scan ? { scanId: subject.scan.scanId } : {}),
        ...(subject.focus ? { findingId: subject.focus.finding.findingId } : {}),
      }),
    };
  }
}
