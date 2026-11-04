import { parse as parseYaml, stringify } from 'yaml';

/**
 * Semgrep rules written by an agent (ADR-043): a closed subset of the rule syntax, at most five rules,
 * ids namespaced under `ai-probe.`, no autofix, no path filters (the host chooses the paths). A rule
 * that was written to find variants of a known finding must first reproduce that seed.
 */
export const MAX_AGENT_RULES = 5;
const MAX_YAML_BYTES = 20_000;

const RULE_KEYS = new Set([
  'id',
  'message',
  'severity',
  'languages',
  'metadata',
  'mode',
  'pattern',
  'patterns',
  'pattern-either',
  'pattern-regex',
  'pattern-not',
  'pattern-not-regex',
  'pattern-inside',
  'pattern-not-inside',
  'pattern-sources',
  'pattern-sinks',
  'pattern-sanitizers',
  'pattern-propagators',
  'options',
]);
const OPERATOR_KEYS = new Set([
  'pattern',
  'patterns',
  'pattern-either',
  'pattern-regex',
  'pattern-not',
  'pattern-not-regex',
  'pattern-inside',
  'pattern-not-inside',
  'focus-metavariable',
  'metavariable-regex',
  'metavariable-pattern',
  'metavariable-comparison',
  'metavariable',
  'regex',
  'comparison',
  'language',
  'by-side-effect',
  'exact',
  'from',
  'to',
  'label',
  'requires',
]);
const LANGUAGES = new Set([
  'javascript',
  'typescript',
  'js',
  'ts',
  'python',
  'java',
  'go',
  'ruby',
  'php',
  'csharp',
  'kotlin',
  'generic',
]);
const SEVERITIES = new Set(['ERROR', 'WARNING', 'INFO', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);

export interface AgentRuleCheck {
  ok: boolean;
  problems: string[];
  /** Normalised YAML with namespaced ids, ready to write into a rule directory. */
  yaml?: string;
  ruleIds: string[];
}

export function validateAgentRules(source: string): AgentRuleCheck {
  const problems: string[] = [];
  if (Buffer.byteLength(source) > MAX_YAML_BYTES) return { ok: false, problems: ['rules exceed 20 KB'], ruleIds: [] };
  let doc: unknown;
  try {
    doc = parseYaml(source);
  } catch (err) {
    return { ok: false, problems: [`invalid YAML: ${(err as Error).message}`], ruleIds: [] };
  }
  const rules = (doc as { rules?: unknown })?.rules;
  if (!Array.isArray(rules) || rules.length === 0)
    return { ok: false, problems: ['expected a top-level "rules" list'], ruleIds: [] };
  if (rules.length > MAX_AGENT_RULES) problems.push(`at most ${MAX_AGENT_RULES} rules per probe`);
  const ids: string[] = [];
  const out = rules.slice(0, MAX_AGENT_RULES).map((rule, i) => {
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
      problems.push(`rule ${i} is not a mapping`);
      return rule;
    }
    const r = rule as Record<string, unknown>;
    for (const key of Object.keys(r)) if (!RULE_KEYS.has(key)) problems.push(`rule ${i}: key "${key}" is not allowed`);
    const id = String(r.id ?? '');
    if (!/^[a-z0-9][a-z0-9._-]{2,80}$/.test(id)) problems.push(`rule ${i}: id must match [a-z0-9][a-z0-9._-]{2,80}`);
    const namespaced = id.startsWith('ai-probe.') ? id : `ai-probe.${id}`;
    if (ids.includes(namespaced)) problems.push(`duplicate rule id ${id}`);
    ids.push(namespaced);
    if (typeof r.message !== 'string' || !r.message) problems.push(`rule ${i}: message is required`);
    if (!SEVERITIES.has(String(r.severity ?? '')))
      problems.push(`rule ${i}: severity must be one of ${[...SEVERITIES].join(', ')}`);
    const langs = r.languages;
    if (!Array.isArray(langs) || langs.length === 0 || langs.some((l) => !LANGUAGES.has(String(l)))) {
      problems.push(`rule ${i}: languages must be a non-empty list of ${[...LANGUAGES].join(', ')}`);
    }
    if (r.mode !== undefined && r.mode !== 'search' && r.mode !== 'taint')
      problems.push(`rule ${i}: mode must be search or taint`);
    const hasPattern = ['pattern', 'patterns', 'pattern-either', 'pattern-regex', 'pattern-sources'].some(
      (k) => k in r,
    );
    if (!hasPattern)
      problems.push(`rule ${i}: needs pattern, patterns, pattern-either, pattern-regex or taint sources`);
    for (const key of Object.keys(r))
      if (key.startsWith('pattern')) checkOperators(r[key], `rule ${i}.${key}`, problems, 0);
    return { ...r, id: namespaced, metadata: { ...(r.metadata as object | undefined), source: 'agent' } };
  });
  if (problems.length) return { ok: false, problems, ruleIds: ids };
  return { ok: true, problems: [], yaml: stringify({ rules: out }), ruleIds: ids };
}

function checkOperators(value: unknown, where: string, problems: string[], depth: number): void {
  if (depth > 8) {
    problems.push(`${where}: nesting too deep`);
    return;
  }
  if (typeof value === 'string' || value === null || value === undefined) return;
  if (Array.isArray(value)) {
    for (const [i, v] of value.entries()) checkOperators(v, `${where}[${i}]`, problems, depth + 1);
    return;
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (!OPERATOR_KEYS.has(k)) problems.push(`${where}: operator "${k}" is not allowed`);
      checkOperators(v, `${where}.${k}`, problems, depth + 1);
    }
  }
}

/** A variant rule counts only when it also finds the seed it was derived from (±2 lines). */
export function reproducesSeed(
  drafts: ReadonlyArray<{ locations: ReadonlyArray<{ path: string; startLine: number }> }>,
  seed: { path: string; line: number },
): boolean {
  return drafts.some((d) => d.locations.some((l) => l.path === seed.path && Math.abs(l.startLine - seed.line) <= 2));
}
