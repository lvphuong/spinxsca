import { describe, expect, it } from 'vitest';
import { categoryFromCwes, EvalCase, normalizeCwe, SpinxscaConfig, severityAtLeast } from '../src/index';

describe('taxonomy', () => {
  it('normalizes CWE strings from scanner metadata', () => {
    expect(
      normalizeCwe("CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"),
    ).toBe('CWE-89');
    expect(normalizeCwe('cwe_78')).toBe('CWE-78');
    expect(normalizeCwe('no cwe here')).toBeUndefined();
  });

  it('maps CWE to category with OTHER fallback', () => {
    expect(categoryFromCwes(['CWE-89'])).toBe('SQL_INJECTION');
    expect(categoryFromCwes(['CWE-99999', 'CWE-79'])).toBe('XSS');
    expect(categoryFromCwes([])).toBe('OTHER');
  });

  it('compares severities', () => {
    expect(severityAtLeast('CRITICAL', 'HIGH')).toBe(true);
    expect(severityAtLeast('MEDIUM', 'HIGH')).toBe(false);
  });
});

describe('config', () => {
  it('rejects unknown keys (closed schema)', () => {
    const result = SpinxscaConfig.safeParse({ version: 1, scan: { unknown_key: true } });
    expect(result.success).toBe(false);
  });

  it('applies defaults and maps lowercase severity', () => {
    const config = SpinxscaConfig.parse({ version: 1, policy: { fail_on_severity: 'high' } });
    expect(config.policy?.fail_on_severity).toBe('HIGH');
    expect(config.policy?.new_findings_only).toBe(true);
  });

  it('routes roles to named models and rejects unknown aliases (ADR-053)', () => {
    const ok = SpinxscaConfig.parse({
      version: 1,
      ai: {
        models: {
          local: { provider: 'ollama', model: 'qwen2.5-coder:14b', base_url: 'http://localhost:11434', num_ctx: 32768 },
          cloud: { provider: 'anthropic', model: 'claude-opus-5-5' },
        },
        routing: { deep: 'cloud', map: 'local', reduce: 'cloud' },
        sharding: { enabled: 'on' },
      },
    });
    expect(ok.ai?.models?.local?.tool_mode).toBe('auto');
    expect(ok.ai?.sharding).toMatchObject({ enabled: 'on', max_shards: 64, token_budget_ratio: 0.35 });
    const missing = SpinxscaConfig.safeParse({
      version: 1,
      ai: { models: { local: { provider: 'ollama', model: 'm', base_url: 'http://h' } }, routing: { deep: 'nope' } },
    });
    expect(missing.success).toBe(false);
    const noUrl = SpinxscaConfig.safeParse({
      version: 1,
      ai: { models: { local: { provider: 'ollama', model: 'm' } } },
    });
    expect(noUrl.success).toBe(false);
  });
});

describe('eval case', () => {
  it('parses ground truth with defaults', () => {
    const parsed = EvalCase.parse({
      id: 'x',
      title: 'x',
      languages: ['javascript'],
      findings: [
        {
          id: 'GT-1',
          category: 'SQL_INJECTION',
          cwe: ['CWE-89'],
          path: 'a.js',
          lines: [1, 2],
          detectable_by: ['sast'],
        },
      ],
    });
    expect(parsed.source).toBe('src');
    expect(parsed.findings[0]?.min_phase).toBe(0);
    expect(parsed.negatives).toEqual([]);
  });
});
