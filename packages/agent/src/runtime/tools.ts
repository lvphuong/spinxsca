import { z } from 'zod';
import type { ToolSpec } from '../llm/types';

export interface ToolContext {
  signal?: AbortSignal;
}

/** A read or action tool exposed to the model. Inputs are validated before `run` is called. */
export interface AgentTool<I = unknown> {
  name: string;
  description: string;
  input: z.ZodType<I>;
  run(input: I, ctx: ToolContext): Promise<string>;
}

/**
 * One-shot structured deliverable (ADR-022). The model must call it to finish; invalid submissions
 * are returned as tool errors so the model can correct them in the same session.
 */
export interface SubmitTool<O> {
  name: string;
  description: string;
  output: z.ZodType<O>;
  /** Host-side checks beyond the schema (for example that cited lines exist); problems are returned to the model. */
  validate?: (output: O) => Promise<string[]> | string[];
}

export function defineTool<I>(tool: AgentTool<I>): AgentTool<I> {
  return tool;
}

export function toolSpec(name: string, description: string, schema: z.ZodType): ToolSpec {
  const json = z.toJSONSchema(schema, { target: 'draft-2020-12', io: 'input', unrepresentable: 'any' }) as Record<
    string,
    unknown
  >;
  delete json.$schema;
  if (json.type !== 'object') throw new Error(`tool ${name} input schema must be an object`);
  return { name, description, inputSchema: json };
}

export function formatIssues(error: z.ZodError): string {
  return error.issues
    .slice(0, 20)
    .map((issue) => `- ${issue.path.length ? issue.path.join('.') : '(root)'}: ${issue.message}`)
    .join('\n');
}
