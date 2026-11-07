import type { ContentBlock } from '../llm/types';
import { boundOutput, type ResultStore } from './result-store';
import { type AgentTool, formatIssues } from './tools';

export type ToolUse = Extract<ContentBlock, { type: 'tool_use' }>;

/** What executing one tool call produced. */
export type ToolOutcome =
  | {
      kind: 'result';
      content: string;
      isError?: boolean;
      /** Policy outcome for the audit trail of the run ("allow L7", "deny L2", ...). */
      decision?: string;
      argsDigest?: string;
      outputDigest?: string;
    }
  /** The call waits for a human (inbox); the session suspends and resumes later. */
  | { kind: 'suspend'; reason: string; approvalId?: string }
  /** A breaker tripped: the session ends after recording this result. */
  | { kind: 'stop'; reason: string; content: string };

export interface ToolExecutor {
  execute(call: ToolUse, ctx: { signal?: AbortSignal }): Promise<ToolOutcome>;
}

export const DEFAULT_OUTPUT_LIMIT = 20_000;

export function capOutput(text: string, limit = DEFAULT_OUTPUT_LIMIT): string {
  if (text.length <= limit) return text;
  return `${text.slice(0, limit)}\n[output truncated: ${text.length - limit} more characters]`;
}

export interface PlainExecutorOptions {
  /** Characters of a result shown inline; the rest goes to the store (ADR-056). */
  inlineChars?: number;
  store?: ResultStore;
}

/** Ungoverned executor used by the fixed-pipeline roles (explain, investigate): validate, run, bound the output. */
export class PlainToolExecutor implements ToolExecutor {
  private readonly tools: Map<string, AgentTool>;

  constructor(
    tools: readonly AgentTool[],
    private readonly options: PlainExecutorOptions = {},
  ) {
    this.tools = new Map(tools.map((t) => [t.name, t]));
  }

  async execute(call: ToolUse, ctx: { signal?: AbortSignal }): Promise<ToolOutcome> {
    const tool = this.tools.get(call.name);
    if (!tool) return { kind: 'result', content: `Unknown tool ${call.name}.`, isError: true };
    const parsed = tool.input.safeParse(call.input);
    if (!parsed.success) {
      return {
        kind: 'result',
        content: `Invalid input for ${call.name}:\n${formatIssues(parsed.error)}`,
        isError: true,
      };
    }
    try {
      const raw = await tool.run(parsed.data, { ...(ctx.signal ? { signal: ctx.signal } : {}) });
      const inline = Math.min(
        tool.outputLimit ?? DEFAULT_OUTPUT_LIMIT,
        this.options.inlineChars ?? DEFAULT_OUTPUT_LIMIT,
      );
      return {
        kind: 'result',
        content: await boundOutput(raw, {
          inlineChars: inline,
          ...(this.options.store ? { store: this.options.store } : {}),
          tool: call.name,
          toolUseId: call.id,
        }),
      };
    } catch (err) {
      return {
        kind: 'result',
        content: `Tool ${call.name} failed: ${err instanceof Error ? err.message : String(err)}`,
        isError: true,
      };
    }
  }
}
