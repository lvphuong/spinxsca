import type { FindingAssessment } from '@spinxsca/schemas';
import { describe, expect, it } from 'vitest';
import { digestOf, stableStringify, ulid } from '../src/ids';
import { manifestChangeCauses } from '../src/manifest';
import { evaluatePolicy } from '../src/policy';
import { redactSecrets } from '../src/redact';

const assessment = (state: FindingAssessment['reconciliationState'], severity: FindingAssessment['severity']) =>
  ({ reconciliationState: state, severity }) as FindingAssessment;

describe('policy', () => {
  const list = [assessment('NEW', 'HIGH'), assessment('EXISTING', 'CRITICAL'), assessment('RESOLVED', 'CRITICAL')];

  it('passes when no threshold is configured', () => {
    expect(evaluatePolicy(list, { newFindingsOnly: true })).toEqual({ passed: true, evaluated: false, violations: [] });
  });

  it('gates only new findings by default', () => {
    expect(evaluatePolicy(list, { failOnSeverity: 'CRITICAL', newFindingsOnly: true }).passed).toBe(true);
    expect(evaluatePolicy(list, { failOnSeverity: 'HIGH', newFindingsOnly: true }).violations).toHaveLength(1);
  });

  it('gates all present findings when requested, never resolved ones', () => {
    expect(evaluatePolicy(list, { failOnSeverity: 'HIGH', newFindingsOnly: false }).violations).toHaveLength(2);
  });
});

describe('redactSecrets', () => {
  it('redacts common credential shapes', () => {
    const input = 'const key = "AKIAIOSFODNN7EXAMPLE";\nconst password = "hunter2hunter2";';
    const { text, redactions } = redactSecrets(input);
    expect(text).toContain('<REDACTED:aws-access-key>');
    expect(text).toContain('password = "<REDACTED:credential>"');
    expect(redactions).toBe(2);
  });

  it('leaves ordinary code alone', () => {
    expect(redactSecrets('db.query(sql, [name])').redactions).toBe(0);
  });
});

describe('ids', () => {
  it('produces sortable ulids', () => {
    const a = ulid(1_000);
    const b = ulid(2_000);
    expect(a).toHaveLength(26);
    expect(a < b).toBe(true);
  });

  it('digests are independent of key order', () => {
    expect(stableStringify({ b: 1, a: { d: 2, c: 3 } })).toBe('{"a":{"c":3,"d":2},"b":1}');
    expect(digestOf({ a: 1, b: 2 })).toBe(digestOf({ b: 2, a: 1 }));
  });
});

describe('manifestChangeCauses', () => {
  const manifest = (scanners: Array<[string, string]>, kb: string | null, content = 'a') =>
    ({
      source: { contentManifestDigest: content },
      ruleBundles: [],
      scannerBundle: {
        scanners: scanners.map(([id, image]) => ({ id, image, adapterVersion: '1', toolVersion: '1' })),
      },
      knowledgeBase: kb ? { snapshotId: kb, digest: kb, ecosystems: [] } : null,
      scope: { exclude: [] },
    }) as never;

  it('reports FIRST_SCAN without a baseline', () => {
    expect(manifestChangeCauses(undefined, {} as never)).toEqual(['FIRST_SCAN']);
  });

  it('separates a narrower scanner set from a scanner upgrade', () => {
    const full = manifest(
      [
        ['semgrep', 's@1'],
        ['osv-scanner', 'o@1'],
      ],
      'kb1',
    );
    expect(manifestChangeCauses(full, manifest([['osv-scanner', 'o@1']], 'kb2'))).toEqual([
      'COVERAGE_CHANGE',
      'ADVISORY_UPDATED',
    ]);
    expect(
      manifestChangeCauses(
        full,
        manifest(
          [
            ['semgrep', 's@2'],
            ['osv-scanner', 'o@1'],
          ],
          'kb1',
          'b',
        ),
      ),
    ).toEqual(['CODE_CHANGE', 'SCANNER_UPGRADED']);
  });
});
