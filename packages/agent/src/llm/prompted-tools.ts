import { repairJson, stripFences } from './json-repair';
import {
  type CompletionRequest,
  type CompletionResult,
  type ContentBlock,
  type LlmProvider,
  type Message,
  type ProviderCapabilities,
  RetryableTurnError,
  type ToolSpec,
} from './types';

/**
 * Prompted tool mode (ADR-054): for models without native tool calling the tool catalog is rendered
 * into the system prompt and calls are parsed back from the reply text. The rest of the runtime sees
 * ordinary `tool_use`/`tool_result` blocks, so governance, budgets and compaction are unchanged.
 */
export const TOOL_CALL_OPEN = '<tool_call>';
export const TOOL_CALL_CLOSE = '</tool_call>';

export interface ParsedToolCall {
  name: string;
  input: unknown;
  raw: string;
}

export interface ParsedToolCalls {
  calls: ParsedToolCall[];
  /** Prose left once the call blocks are removed. */
  text: string;
  problems: string[];
}

const PROTOCOL = [
  '## Tools',
  'You can call the tools listed below. To call one, end your message with exactly one block of this form and nothing after it:',
  `${TOOL_CALL_OPEN}{"name": "<tool name>", "arguments": { ... }}${TOOL_CALL_CLOSE}`,
  "Arguments must be valid JSON (double quotes, no trailing commas) that matches the tool's argument schema. Call at most one tool per message; wait for its result before the next call. Results come back as <tool_result> blocks.",
].join('\n');

/** Compact rendering of the tool catalog for a system prompt. */
export function renderToolsForPrompt(tools: readonly ToolSpec[], options: { maxCharsPerTool?: number } = {}): string {
  const cap = options.maxCharsPerTool ?? 2_500;
  const lines = [PROTOCOL, ''];
  for (const tool of tools) {
    const schema = renderSchema(tool.inputSchema, 0);
    const body = `### ${tool.name}\n${tool.description.trim()}\nArguments: ${schema}`;
    lines.push(body.length > cap ? `${body.slice(0, cap - 1)}…` : body, '');
  }
  return lines.join('\n').trimEnd();
}

type JsonSchema = Record<string, unknown>;

function renderSchema(schema: JsonSchema, depth: number): string {
  if (depth > 6) return '…';
  if (Array.isArray(schema.enum)) return schema.enum.map((v) => JSON.stringify(v)).join(' | ');
  if (Array.isArray(schema.anyOf))
    return (schema.anyOf as JsonSchema[]).map((s) => renderSchema(s, depth + 1)).join(' | ');
  const type = Array.isArray(schema.type) ? (schema.type as string[]).join('|') : (schema.type as string | undefined);
  if (type === 'object' || schema.properties) {
    const props = (schema.properties ?? {}) as Record<string, JsonSchema>;
    const required = new Set((schema.required as string[] | undefined) ?? []);
    const entries = Object.entries(props).map(([key, value]) => {
      const desc =
        typeof value.description === 'string' && depth === 0 ? ` /* ${value.description.slice(0, 120)} */` : '';
      return `"${key}"${required.has(key) ? '' : '?'}: ${renderSchema(value, depth + 1)}${desc}`;
    });
    return entries.length ? `{ ${entries.join(', ')} }` : '{}';
  }
  if (type === 'array') {
    const items = (schema.items ?? {}) as JsonSchema;
    return `${renderSchema(items, depth + 1)}[]`;
  }
  if (schema.const !== undefined) return JSON.stringify(schema.const);
  return type ?? 'any';
}

/** Parses tool calls written as `<tool_call>` blocks, fenced JSON or a bare `{"name":…,"arguments":…}` object. */
export function parseToolCalls(text: string, known: ReadonlySet<string>): ParsedToolCalls {
  const calls: ParsedToolCall[] = [];
  const problems: string[] = [];
  let rest = text;
  const accept = (raw: string): boolean => {
    const repaired = repairJson(raw);
    if (!repaired) {
      problems.push(`tool call is not valid JSON: ${raw.slice(0, 120)}`);
      return false;
    }
    const value = repaired.value as Record<string, unknown> | null;
    if (!value || typeof value !== 'object') {
      problems.push('tool call must be a JSON object');
      return false;
    }
    const name = typeof value.name === 'string' ? value.name : typeof value.tool === 'string' ? value.tool : undefined;
    if (!name) {
      problems.push('tool call has no "name"');
      return false;
    }
    if (!known.has(name)) {
      problems.push(`unknown tool "${name}"; available: ${[...known].join(', ')}`);
      return false;
    }
    const args = value.arguments ?? value.parameters ?? value.input ?? {};
    let input: unknown = args;
    if (typeof args === 'string') {
      const inner = repairJson(args);
      if (!inner) {
        problems.push(`arguments of ${name} are not valid JSON`);
        return false;
      }
      input = inner.value;
    }
    calls.push({ name, input, raw });
    return true;
  };

  const tagged = new RegExp(`${TOOL_CALL_OPEN}([\\s\\S]*?)(?:${TOOL_CALL_CLOSE}|$)`, 'g');
  if (text.includes(TOOL_CALL_OPEN)) {
    for (const m of text.matchAll(tagged)) accept((m[1] as string).trim());
    rest = text.replace(tagged, '').trim();
    return { calls, text: rest, problems };
  }
  const fences = [...text.matchAll(/```(?:json|JSON)?\s*\n?([\s\S]*?)```/g)];
  const candidates = fences.map((m) => (m[1] as string).trim()).filter((s) => /"?(name|tool)"?\s*:/.test(s));
  if (candidates.length) {
    for (const c of candidates) accept(c);
    rest = text.replace(/```(?:json|JSON)?\s*\n?[\s\S]*?```/g, '').trim();
    return { calls, text: rest, problems };
  }
  const bare = /\{[\s\S]*"(?:name|tool)"\s*:[\s\S]*\}/.exec(text);
  if (bare) {
    const span = stripFences(bare[0]);
    if (accept(span)) rest = text.replace(bare[0], '').trim();
  }
  return { calls, text: rest, problems };
}

/** Renders a transcript whose tool blocks become text the model can read in prompted mode. */
export function toPromptedMessages(messages: readonly Message[]): Message[] {
  const names = new Map<string, string>();
  for (const m of messages) for (const b of m.content) if (b.type === 'tool_use') names.set(b.id, b.name);
  return messages.map((m) => {
    const parts: string[] = [];
    for (const b of m.content) {
      if (b.type === 'text') parts.push(b.text);
      else if (b.type === 'tool_use')
        parts.push(`${TOOL_CALL_OPEN}${JSON.stringify({ name: b.name, arguments: b.input ?? {} })}${TOOL_CALL_CLOSE}`);
      else if (b.type === 'tool_result')
        parts.push(
          `<tool_result name="${names.get(b.toolUseId) ?? 'tool'}"${b.isError ? ' error="true"' : ''}>\n${b.content}\n</tool_result>`,
        );
    }
    return { role: m.role, content: [{ type: 'text', text: parts.join('\n') || '(empty)' }] };
  });
}

/**
 * Wraps a provider so tools are offered through the prompt. Capabilities report `toolMode:
 * 'prompted'`; parse failures surface as `RetryableTurnError('parse')` carrying the raw reply, which
 * the session turns into a correction request.
 */
export function withPromptedTools(inner: LlmProvider): LlmProvider {
  let turn = 0;
  return {
    id: inner.id,
    model: inner.model,
    capabilities(): ProviderCapabilities {
      return { ...inner.capabilities(), tools: true, toolMode: 'prompted' };
    },
    ...(inner.countTokens
      ? {
          countTokens: (r: Parameters<NonNullable<LlmProvider['countTokens']>>[0]) =>
            (inner.countTokens as NonNullable<LlmProvider['countTokens']>)(r),
        }
      : {}),
    async complete(request: CompletionRequest, options): Promise<CompletionResult> {
      if (request.tools.length === 0) return inner.complete(request, options);
      turn++;
      const known = new Set(request.tools.map((t) => t.name));
      const result = await inner.complete(
        {
          ...request,
          system: `${request.system}\n\n${renderToolsForPrompt(request.tools)}`,
          messages: toPromptedMessages(request.messages),
          tools: [],
          toolChoice: undefined,
        },
        options,
      );
      const text = result.content.flatMap((b) => (b.type === 'text' ? [b.text] : [])).join('\n');
      const parsed = parseToolCalls(text, known);
      if (parsed.problems.length) throw new RetryableTurnError(parsed.problems.join('; '), 'parse', { rawText: text });
      if (parsed.calls.length === 0 && request.toolChoice === 'required' && result.stopReason !== 'max_tokens')
        throw new RetryableTurnError('the reply contained no tool call', 'parse', { rawText: text });
      const content: ContentBlock[] = [];
      if (parsed.text) content.push({ type: 'text', text: parsed.text });
      for (const [i, c] of parsed.calls.entries())
        content.push({ type: 'tool_use', id: `pt_${turn}_${i}`, name: c.name, input: c.input });
      return {
        ...result,
        content,
        stopReason: parsed.calls.length ? 'tool_use' : result.stopReason,
      };
    },
  };
}
