import { AgentRunRecord, RISK_RANK, type RiskClass, TOOL_RISK } from '@spinxsca/schemas';
import { z } from 'zod';

/**
 * Persona manifest (ADR-046), the YAML front matter of prompts/personas/<id>.md. Tools come from the
 * closed catalog; the host checks them against the persona's ceiling so a prompt edit cannot hand
 * the lead an executing tool or the validator a patch tool.
 */
export const PersonaManifest = z.strictObject({
  id: z.string().regex(/^[a-z][a-z0-9-]*$/),
  role: AgentRunRecord.shape.role,
  description: z.string().min(1),
  tools: z.array(z.string()).min(1),
  skills: z.array(z.string()).default([]),
  /** Model tier: deep (main model) or fast (explore, dedupe). */
  tier: z.enum(['deep', 'fast']).default('deep'),
  max_steps: z.number().int().positive().optional(),
  max_tool_calls: z.number().int().positive().optional(),
});
export type PersonaManifest = z.infer<typeof PersonaManifest>;

/** Highest risk each persona may hold, independent of its prompt. */
export const PERSONA_RISK_CEILING: Readonly<Record<string, RiskClass>> = {
  lead: 'RECORD',
  explore: 'READ',
  dedupe: 'RECORD',
  appsec: 'ANALYZE',
  dependency: 'ANALYZE',
  secrets: 'ANALYZE',
  iac: 'ANALYZE',
  validator: 'EXEC_REPO_CODE',
  exploit: 'EXEC_REPO_CODE',
  fixer: 'WRITE_REPO',
  verifier: 'EXEC_REPO_CODE',
  // Phase 6 (ADR-049): recon and logic audits analyse; the critic only reads and records.
  recon: 'ANALYZE',
  logic: 'ANALYZE',
  critic: 'RECORD',
};

/** Tools a persona may never hold whatever its ceiling (separation of powers). */
const FORBIDDEN: Readonly<Record<string, readonly string[]>> = {
  validator: ['patch_propose', 'request_apply'],
  verifier: ['patch_propose', 'request_apply', 'harness_write'],
  exploit: ['patch_propose', 'request_apply', 'submit_verdict'],
  fixer: ['submit_verdict', 'validation_run'],
  recon: ['submit_verdict', 'propose_disposition', 'patch_propose', 'validation_run'],
  critic: ['semgrep_rule', 'run_scanner', 'shell_exec', 'submit_verdict', 'propose_disposition'],
};

export function checkManifest(m: PersonaManifest): string[] {
  const problems: string[] = [];
  const ceiling = PERSONA_RISK_CEILING[m.id];
  if (!ceiling) problems.push(`persona ${m.id} has no risk ceiling`);
  for (const tool of m.tools) {
    const risk = TOOL_RISK[tool];
    if (!risk) {
      problems.push(`${m.id}: unknown tool ${tool}`);
      continue;
    }
    // request_* tools route to a human (L6), so they do not count against the ceiling.
    if (ceiling && !tool.startsWith('request_') && RISK_RANK[risk] > RISK_RANK[ceiling]) {
      problems.push(`${m.id}: ${tool} (${risk}) exceeds the ${ceiling} ceiling`);
    }
    if (FORBIDDEN[m.id]?.includes(tool)) problems.push(`${m.id}: ${tool} is forbidden for this persona`);
  }
  return problems;
}
