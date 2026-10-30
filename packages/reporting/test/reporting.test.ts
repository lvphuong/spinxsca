import type { ReportEntry, ScanReportModel } from '@spinxsca/core';
import { describe, expect, it } from 'vitest';
import { renderJson, renderMarkdown, renderSarif } from '../src/index';

const now = '2026-10-29T00:00:00.000Z';
const d = (c: string) => `sha256:${c.repeat(64)}` as `sha256:${string}`;

function entry(
  id: string,
  state: ReportEntry['assessment']['reconciliationState'],
  severity: ReportEntry['assessment']['severity'],
): ReportEntry {
  return {
    finding: {
      findingId: id,
      projectId: 'p',
      seq: 1,
      category: 'SQL_INJECTION',
      ruleFamily: 'sqli',
      title: 'SQL injection | from request',
      cwe: ['CWE-89'],
      canonicalFingerprint: 'spx1:abc',
      fingerprintAlgorithm: 'spinxsca/fp/v1',
      firstSeenScanId: 'scan_1',
      createdAt: now,
    },
    assessment: {
      assessmentId: 'a',
      findingId: id,
      scanId: 'scan_2',
      occurrenceId: 'o',
      reconciliationState: state,
      classification: 'POTENTIAL',
      severity,
      confidence: 'MEDIUM',
      exploitability: 'UNKNOWN',
      verificationLevel: 'L1_STATIC',
      evidenceIds: ['ev'],
      counterevidence: [],
      missingEvidence: ['Not yet validated.'],
      reasoningSummary: 'r',
      changeCauses: state === 'NEW' ? ['CODE_CHANGE'] : [],
      assessedBy: 'host',
      assessedAt: now,
    },
    occurrence: {
      occurrenceId: 'o',
      findingId: id,
      scanId: 'scan_2',
      snapshotId: 's',
      locations: [
        { path: 'routes/users.js', startLine: 10, endLine: 10, startColumn: 31, endColumn: 34, role: 'primary' },
      ],
      fingerprint: 'spx1:abc',
      anchor: { path: 'routes/users.js', symbol: '', shape: 'x', instance: 0 },
      ruleIds: ['spinxsca-core.js-sql-injection'],
      candidateIds: ['c'],
      evidenceIds: ['ev'],
    },
    candidates: [],
    evidence: [
      {
        evidenceId: 'ev',
        kind: 'CODE_SNIPPET',
        producedBy: 'semgrep',
        snapshotId: 's',
        locations: [],
        excerpt: '   10 | await db.query(sql);',
        summary: 'primary at routes/users.js:10',
      },
    ],
  };
}

const model: ScanReportModel = {
  scan: {
    scanId: 'scan_2',
    projectId: 'p',
    repositoryId: 'r',
    snapshotId: 's',
    mode: 'FULL',
    status: 'COMPLETED',
    manifest: {
      schemaVersion: 1,
      scanId: 'scan_2',
      engineVersion: '0.0.0',
      source: { snapshotId: 's', contentManifestDigest: d('a') },
      scannerBundle: {
        digest: d('b'),
        scanners: [
          {
            id: 'semgrep',
            adapterVersion: '0.1.0',
            toolVersion: '1.182.1',
            image: `semgrep/semgrep:1.182.1@${d('c')}`,
          },
        ],
      },
      ruleBundles: [{ id: 'spinxsca-core', version: 'v', digest: d('e'), ruleCount: 4 }],
      knowledgeBase: null,
      aiPolicy: { level: 'off', policyVersion: 'x' },
      scanMode: 'FULL',
      baselineScanId: 'scan_1',
      scope: { exclude: [] },
      requestedAt: now,
    },
    manifestDigest: d('f'),
    baselineScanId: 'scan_1',
    requestedAt: now,
    completedAt: now,
    summary: {
      candidates: 2,
      findings: 2,
      bySeverity: { HIGH: 1, MEDIUM: 1 },
      byState: { NEW: 1, EXISTING: 1, RESOLVED: 1 },
      completeness: 'COMPLETE',
    },
  },
  project: { projectId: 'p', name: 'demo', createdAt: now },
  repository: { repositoryId: 'r', projectId: 'p', rootPath: '/x', createdAt: now },
  snapshot: {
    snapshotId: 's',
    repositoryId: 'r',
    kind: 'WORKSPACE',
    contentManifestDigest: d('a'),
    fileCount: 3,
    fileListDigest: d('1'),
    capturedAt: now,
  },
  tasks: [],
  present: [entry('SPX-000002', 'NEW', 'HIGH'), entry('SPX-000001', 'EXISTING', 'MEDIUM')],
  suppressed: [],
  resolved: [entry('SPX-000003', 'RESOLVED', 'HIGH')],
  notReevaluated: [],
  aiRuns: [],
};

describe('renderSarif', () => {
  const sarif = JSON.parse(renderSarif(model));
  const run = sarif.runs[0];

  it('emits a SARIF 2.1.0 run with one rule per scanner rule', () => {
    expect(sarif.version).toBe('2.1.0');
    expect(run.tool.driver.name).toBe('spinxsca');
    expect(run.tool.driver.rules.map((r: { id: string }) => r.id)).toEqual(['spinxsca-core.js-sql-injection']);
    expect(run.tool.driver.rules[0].properties['security-severity']).toBe('8.0');
  });

  it('includes only present findings with fingerprints and baseline state', () => {
    expect(run.results).toHaveLength(2);
    expect(run.results[0].partialFingerprints).toEqual({ 'spinxsca/fp/v1': 'spx1:abc' });
    expect(run.results.map((r: { baselineState: string }) => r.baselineState)).toEqual(['new', 'unchanged']);
    expect(run.results[0].locations[0].physicalLocation.region).toEqual({
      startLine: 10,
      endLine: 10,
      startColumn: 31,
      endColumn: 34,
    });
    expect(run.results[1].level).toBe('warning');
  });
});

describe('renderMarkdown', () => {
  const md = renderMarkdown(model);

  it('states the manifest, summary, findings and resolved sections', () => {
    expect(md).toContain('## Analysis manifest');
    expect(md).toContain('| Rule bundle | spinxsca-core · 4 rules');
    expect(md).toContain('### SPX-000002 · HIGH · SQL injection \\| from request');
    expect(md).toContain('## Resolved since baseline');
    expect(md).toContain('await db.query(sql);');
    expect(md).toContain('**Why it appears:** code change');
  });
});

describe('renderJson', () => {
  it('is parseable and versioned', () => {
    const json = JSON.parse(renderJson(model));
    expect(json.schema).toBe('spinxsca/report/v1');
    expect(json.findings).toHaveLength(2);
    expect(json.resolved[0].finding.findingId).toBe('SPX-000003');
  });
});
