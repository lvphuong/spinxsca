import { TOOL_CALL_CLOSE, TOOL_CALL_OPEN } from './prompted-tools';
import type { CompletionRequest, CompletionResult, ContentBlock, LlmProvider, ProviderCapabilities } from './types';

/**
 * Test double for a weak local model (ADR-054): declares prompted tools and a small window, writes
 * its first tool call as prose with a trailing comma, the second as a fenced JSON block, and only
 * then behaves. Wrap it with `withPromptedTools` to exercise parsing, JSON repair and the
 * correction turn end to end without a model.
 */
export function weakModelProvider(inner: LlmProvider, options: { maxContext?: number } = {}): LlmProvider {
  let calls = 0;
  const asText = (b: Extract<ContentBlock, { type: 'tool_use' }>, style: 'hermes' | 'fence'): string => {
    const body = JSON.stringify({ name: b.name, arguments: b.input ?? {} });
    if (style === 'hermes') return `Let me do that.\n${TOOL_CALL_OPEN}${body.replace(/}$/, ',}')}${TOOL_CALL_CLOSE}`;
    return `Here is the call:\n\`\`\`json\n${body}\n\`\`\``;
  };
  return {
    id: inner.id,
    model: `${inner.model}-weak`,
    capabilities(): ProviderCapabilities {
      return {
        ...inner.capabilities(),
        toolMode: 'prompted',
        maxContext: options.maxContext ?? 16_000,
        maxOutput: 2_000,
      };
    },
    async complete(request: CompletionRequest, opts): Promise<CompletionResult> {
      const result = await inner.complete(request, opts);
      const use = result.content.find((b): b is Extract<ContentBlock, { type: 'tool_use' }> => b.type === 'tool_use');
      if (!use) return result;
      calls++;
      if (calls > 2)
        return {
          ...result,
          content: [{ type: 'text', text: asText(use, 'hermes').replace(',}', '}') }],
          stopReason: 'end_turn',
        };
      return {
        ...result,
        content: [{ type: 'text', text: asText(use, calls === 1 ? 'hermes' : 'fence') }],
        stopReason: 'end_turn',
      };
    },
  };
}
