import type { JudgeModel } from '@spinxsca/governance';
import type { LlmProvider } from './types';

/** Reviewer model over any provider: one completion, no tools, short output (ADR-041). */
export function providerJudge(provider: LlmProvider, options: { maxTokens?: number } = {}): JudgeModel {
  return {
    id: `${provider.id}/${provider.model}`,
    async judge(input, signal) {
      const result = await provider.complete(
        {
          system: input.system,
          messages: [{ role: 'user', content: [{ type: 'text', text: input.prompt }] }],
          tools: [],
          maxTokens: options.maxTokens ?? 400,
          effort: 'low',
          metadata: { role: 'reviewer' },
        },
        { ...(signal ? { signal } : {}) },
      );
      if (result.stopReason === 'refusal') return '{"verdict":"unsure","reason":"reviewer refused"}';
      return result.content
        .filter((b) => b.type === 'text')
        .map((b) => (b as { text: string }).text)
        .join('\n');
    },
  };
}
