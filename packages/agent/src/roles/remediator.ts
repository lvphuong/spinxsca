import type { ExplainSubject, Remediator, SourceTree } from '@spinxsca/core';
import { type AgentRunRecord, PatchProposal } from '@spinxsca/schemas';
import { costOf } from '../llm/pricing';
import type { Effort, LlmProvider } from '../llm/types';
import type { PromptBundle } from '../prompts/bundle';
import { runAgent } from '../runtime/loop';
import { checkCitations, createCodeTools } from '../tools/code-tools';
import { EXPLAIN_POLICY_VERSION, explainPrompt, toRecord } from './explainer';

/** Remediation role (docs/architecture/03 section 10): proposes line edits; the host verifies them. */
export class AgentRemediator implements Remediator {
  readonly info: Remediator['info'];

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
      policyVersion: `${EXPLAIN_POLICY_VERSION}+remediate-v1`,
    };
  }

  async propose(
    subject: ExplainSubject,
    source: SourceTree,
    signal?: AbortSignal,
  ): Promise<{ proposal?: PatchProposal; run: AgentRunRecord }> {
    const startedAt = new Date().toISOString();
    const ctx = { source, paths: subject.snapshotPaths, redactions: subject.redactions, findings: subject.related };
    const provider = this.options.provider();
    const result = await runAgent({
      role: 'remediation',
      provider,
      system: this.options.prompts.render('remediation'),
      prompt: `Fix this finding.\n\n${explainPrompt(subject)}`,
      tools: createCodeTools(ctx),
      submit: {
        name: 'submit_patch',
        description: 'Submit the patch as line-range edits. Call exactly once when done.',
        output: PatchProposal,
        validate: (proposal) =>
          checkCitations(
            ctx,
            proposal.edits.map((e) => ({ path: e.path, startLine: e.startLine, endLine: e.endLine })),
          ),
      },
      budget: { maxSteps: 20, maxToolCalls: 50, maxOutputTokens: 32_000, maxTotalTokens: 400_000 },
      ...(this.options.effort ? { effort: this.options.effort } : {}),
      ...(signal ? { signal } : {}),
      scanId: subject.scan.scanId,
      costOf,
      ...(this.options.maxCostUsd ? { maxCostUsd: this.options.maxCostUsd } : {}),
    });
    return {
      ...(result.output ? { proposal: result.output } : {}),
      run: toRecord(result, {
        role: 'remediation',
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
