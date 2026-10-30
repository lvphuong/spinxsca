import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  imageRef,
  loadRuleBundle,
  normalizeSemgrepResults,
  PINNED_IMAGES,
  SemgrepAdapter,
  type SemgrepJson,
} from '../src/index';

const RULES = resolve(__dirname, '../../../rules/semgrep/spinxsca-core');
const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

// Shape copied from a real `semgrep scan --json-output` run without login (lines/fingerprint withheld).
const output: SemgrepJson = {
  version: '1.182.1',
  results: [
    {
      check_id: 'js-sql-injection',
      path: 'routes/users.js',
      start: { line: 10, col: 31 },
      end: { line: 10, col: 34 },
      extra: {
        message: 'HTTP request input flows into a SQL statement string.',
        severity: 'ERROR',
        fingerprint: 'requires login',
        metadata: {
          cwe: ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"],
          confidence: 'MEDIUM',
          spinxsca: { category: 'SQL_INJECTION', family: 'sqli', title: 'SQL injection from HTTP request input' },
        },
      },
    },
    {
      check_id: 'third-party.rule-without-spinxsca-metadata',
      path: './lib/x.js',
      start: { line: 3, col: 1 },
      end: { line: 3, col: 9 },
      extra: { message: 'm', severity: 'WARNING', metadata: { cwe: 'CWE-79: XSS' } },
    },
    {
      check_id: 'js-sql-injection',
      path: 'node_modules/pkg/index.js',
      start: { line: 1, col: 1 },
      end: { line: 1, col: 2 },
      extra: { message: 'm', severity: 'ERROR' },
    },
  ],
  errors: [],
  paths: { scanned: ['routes/users.js', 'lib/x.js', 'node_modules/pkg/index.js'] },
};

describe('normalizeSemgrepResults', () => {
  const drafts = normalizeSemgrepResults(output, {
    bundleOf: (id) => (id === 'js-sql-injection' ? 'spinxsca-core' : undefined),
    allowedPaths: new Set(['routes/users.js', 'lib/x.js']),
  });

  it('drops results outside the snapshot', () => {
    expect(drafts).toHaveLength(2);
  });

  it('maps rule metadata onto the taxonomy', () => {
    expect(drafts[0]).toMatchObject({
      scanner: 'semgrep',
      ruleId: 'spinxsca-core.js-sql-injection',
      ruleFamily: 'sqli',
      category: 'SQL_INJECTION',
      cwe: ['CWE-89'],
      severityHint: 'HIGH',
      confidenceHint: 'MEDIUM',
      title: 'SQL injection from HTTP request input',
    });
    expect(drafts[0]?.locations[0]).toEqual({
      path: 'routes/users.js',
      startLine: 10,
      endLine: 10,
      startColumn: 31,
      endColumn: 34,
      role: 'primary',
    });
    expect(drafts[0]?.scannerFingerprint).toBeUndefined();
  });

  it('falls back to CWE mapping and humanized titles', () => {
    expect(drafts[1]).toMatchObject({
      category: 'XSS',
      ruleFamily: 'xss',
      severityHint: 'MEDIUM',
      title: 'Rule without spinxsca metadata',
      locations: [expect.objectContaining({ path: 'lib/x.js' })],
    });
  });
});

describe('rule bundles', () => {
  it('loads the shipped spinxsca-core bundle with a content digest', async () => {
    const bundle = await loadRuleBundle('spinxsca-core', RULES);
    expect(bundle.ruleIds).toEqual([
      'js-command-injection',
      'js-path-traversal',
      'js-sql-injection',
      'js-ssrf',
      'py-command-injection',
      'react-dangerously-set-inner-html',
    ]);
    expect(bundle.ref.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(bundle.ref.ruleCount).toBe(6);
  });

  it('changes digest when a rule changes and rejects bundles without rules', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'spx-rules-'));
    dirs.push(dir);
    writeFileSync(
      join(dir, 'a.yaml'),
      'rules:\n  - id: a\n    pattern: x\n    message: m\n    languages: [js]\n    severity: INFO\n',
    );
    const first = await loadRuleBundle('t', dir);
    writeFileSync(
      join(dir, 'a.yaml'),
      'rules:\n  - id: a\n    pattern: y\n    message: m\n    languages: [js]\n    severity: INFO\n',
    );
    const second = await loadRuleBundle('t', dir);
    expect(second.ref.digest).not.toBe(first.ref.digest);
    const empty = mkdtempSync(join(tmpdir(), 'spx-rules-'));
    dirs.push(empty);
    await expect(loadRuleBundle('e', empty)).rejects.toThrow('contains no rules');
  });
});

describe('SemgrepAdapter', () => {
  it('describes a pinned image and applies only to supported files', () => {
    const adapter = new SemgrepAdapter({ bundles: [{ id: 'spinxsca-core', dir: RULES }] });
    expect(adapter.describe().image).toBe(imageRef(PINNED_IMAGES.semgrep));
    expect(adapter.describe().image).toMatch(/@sha256:[0-9a-f]{64}$/);
    expect(adapter.applies([{ path: 'README.md', digest: 'sha256:x' as never, size: 1 }])).toBe(false);
    expect(adapter.applies([{ path: 'src/a.tsx', digest: 'sha256:x' as never, size: 1 }])).toBe(true);
  });
});
