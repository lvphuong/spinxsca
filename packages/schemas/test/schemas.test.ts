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
