import type {
  Finding,
  FindingAssessment,
  FindingCandidate,
  FindingOccurrence,
  FingerprintAnchor,
} from '@spinxsca/schemas';
import { describe, expect, it } from 'vitest';
import type { CoverageOracle } from '../src/coverage';
import { groupCandidates, type PriorFinding, reconcile } from '../src/reconcile';

let counter = 0;
const newId = (prefix: string) => `${prefix}_${++counter}`;
const now = '2026-10-29T00:00:00.000Z';

function candidate(
  fp: string,
  anchor: Partial<FingerprintAnchor> = {},
  overrides: Partial<FindingCandidate> = {},
): FindingCandidate {
  return {
    candidateId: `cand_${fp}`,
    scanId: 'scan_2',
    scanTaskId: 'task_1',
    scanner: 'semgrep',
    ruleId: 'spinxsca.js-sqli',
    ruleFamily: 'sqli',
    category: 'SQL_INJECTION',
    cwe: ['CWE-89'],
    title: 'SQL injection',
    message: 'm',
    severityHint: 'HIGH',
    confidenceHint: 'MEDIUM',
    locations: [{ path: anchor.path ?? 'a.js', startLine: 10, endLine: 10, role: 'primary' }],
    fingerprints: {
      semantic: fp,
      algorithm: 'spinxsca/fp/v1',
      anchor: { path: 'a.js', symbol: 'heuristic:search', shape: 'shape1', instance: 0, ...anchor },
    },
    evidenceIds: [],
    ...overrides,
  };
}

function prior(
  findingId: string,
  fp: string,
  state: FindingAssessment['reconciliationState'],
  anchor: Partial<FingerprintAnchor> = {},
): PriorFinding {
  const finding: Finding = {
    findingId,
    projectId: 'p',
    seq: Number(findingId.slice(-1)),
    category: 'SQL_INJECTION',
    ruleFamily: 'sqli',
    title: 'SQL injection',
    cwe: ['CWE-89'],
    canonicalFingerprint: fp,
    fingerprintAlgorithm: 'spinxsca/fp/v1',
    firstSeenScanId: 'scan_1',
    createdAt: now,
  };
  const occurrence: FindingOccurrence = {
    occurrenceId: `occ_${findingId}`,
    findingId,
    scanId: 'scan_1',
    snapshotId: 'snap_1',
    locations: [{ path: anchor.path ?? 'a.js', startLine: 10, endLine: 10, role: 'primary' }],
    fingerprint: fp,
    anchor: { path: 'a.js', symbol: 'heuristic:search', shape: 'shape1', instance: 0, ...anchor },
    ruleIds: ['spinxsca.js-sqli'],
    candidateIds: ['c'],
    evidenceIds: [],
  };
  const assessment: FindingAssessment = {
    assessmentId: `asm_${findingId}`,
    findingId,
    scanId: 'scan_1',
    occurrenceId: occurrence.occurrenceId,
    reconciliationState: state,
    classification: 'POTENTIAL',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    exploitability: 'UNKNOWN',
    verificationLevel: 'L1_STATIC',
    evidenceIds: [],
    counterevidence: [],
    missingEvidence: [],
    reasoningSummary: '',
    changeCauses: [],
    assessedBy: 'host',
    assessedAt: now,
  };
  return { finding, baselineAssessment: assessment, latestAssessment: assessment, latestOccurrence: occurrence };
}

const proves = (proven: boolean): CoverageOracle => ({
  provesAbsence: () => ({ proven, reason: proven ? 'covered' : 'not covered' }),
});

function run(candidates: FindingCandidate[], priorFindings: PriorFinding[], coverage = proves(true)) {
  return reconcile({
    projectId: 'p',
    scanId: 'scan_2',
    snapshotId: 'snap_2',
    algorithm: 'spinxsca/fp/v1',
    groups: groupCandidates(candidates),
    prior: priorFindings,
    fingerprintIndex: new Map(priorFindings.map((p) => [p.finding.canonicalFingerprint, p.finding.findingId])),
    coverage,
    causesFor: () => (priorFindings.length ? ['CODE_CHANGE'] : ['FIRST_SCAN']),
    nextSeq: priorFindings.length + 1,
    now,
    newId,
  });
}

describe('reconcile', () => {
  it('creates NEW findings on the first scan', () => {
    const result = run([candidate('fp1'), candidate('fp2', { instance: 1 })], []);
    expect(result.newFindings.map((f) => f.findingId)).toEqual(['SPX-000001', 'SPX-000002']);
    expect(result.assessments.every((a) => a.reconciliationState === 'NEW')).toBe(true);
    expect(result.assessments[0]?.changeCauses).toEqual(['FIRST_SCAN']);
    expect(result.assessments[0]?.verificationLevel).toBe('L1_STATIC');
  });

  it('merges candidates with the same fingerprint into one occurrence', () => {
    const result = run(
      [candidate('fp1'), candidate('fp1', {}, { candidateId: 'cand_other', ruleId: 'spinxsca.js-sqli-2' })],
      [],
    );
    expect(result.newFindings).toHaveLength(1);
    expect(result.occurrences[0]?.candidateIds).toHaveLength(2);
    expect(result.occurrences[0]?.ruleIds).toEqual(['spinxsca.js-sqli', 'spinxsca.js-sqli-2']);
  });

  it('keeps identity when the fingerprint matches', () => {
    const result = run([candidate('fp1')], [prior('SPX-000001', 'fp1', 'NEW')]);
    expect(result.newFindings).toHaveLength(0);
    expect(result.stateByFinding.get('SPX-000001')).toBe('EXISTING');
    expect(result.matchEvents[0]?.method).toBe('EXACT_FINGERPRINT');
  });

  it('marks RESOLVED only when coverage proves absence', () => {
    expect(run([], [prior('SPX-000001', 'fp1', 'EXISTING')], proves(true)).stateByFinding.get('SPX-000001')).toBe(
      'RESOLVED',
    );
    const carried = run([], [prior('SPX-000001', 'fp1', 'EXISTING')], proves(false));
    expect(carried.stateByFinding.get('SPX-000001')).toBe('NOT_REEVALUATED');
    expect(carried.assessments[0]?.severity).toBe('HIGH');
    expect(carried.assessments[0]?.missingEvidence[0]).toBe('not covered');
  });

  it('reopens a previously resolved finding', () => {
    const p = prior('SPX-000001', 'fp1', 'RESOLVED');
    const result = run([candidate('fp1')], [p]);
    expect(result.stateByFinding.get('SPX-000001')).toBe('REOPENED');
  });

  it('matches a relocated finding (file renamed, same symbol and shape) and records an alias', () => {
    const result = run([candidate('fp-new', { path: 'b.js' })], [prior('SPX-000001', 'fp1', 'EXISTING')]);
    expect(result.stateByFinding.get('SPX-000001')).toBe('EXISTING');
    expect(result.fingerprintAliases).toEqual([
      { findingId: 'SPX-000001', fingerprint: 'fp-new', algorithm: 'spinxsca/fp/v1' },
    ]);
    expect(result.matchEvents[0]?.method).toBe('RELOCATED');
  });

  it('flags near matches for review instead of merging or resolving', () => {
    const result = run([candidate('fp-changed', { shape: 'shape2' })], [prior('SPX-000001', 'fp1', 'EXISTING')]);
    expect(result.newFindings).toHaveLength(1);
    expect(result.stateByFinding.get('SPX-000002')).toBe('NEEDS_RECONCILIATION');
    expect(result.stateByFinding.get('SPX-000001')).toBe('NEEDS_RECONCILIATION');
    expect(result.matchEvents.find((e) => e.findingId === 'SPX-000002')?.method).toBe('NEAR');
  });

  it('treats a new advisory on the same package as a new finding, not a near match', () => {
    const sca = (fp: string, vuln: string) =>
      candidate(
        fp,
        { path: 'package-lock.json', symbol: 'purl:pkg:npm/lodash', shape: `vuln:${vuln}` },
        {
          category: 'VULNERABLE_DEPENDENCY',
          ruleFamily: 'vulnerable-dependency',
        },
      );
    const old = prior('SPX-000001', 'fp-a', 'NEW', {
      path: 'package-lock.json',
      symbol: 'purl:pkg:npm/lodash',
      shape: 'vuln:GHSA-a',
    });
    old.finding.category = 'VULNERABLE_DEPENDENCY';
    old.finding.ruleFamily = 'vulnerable-dependency';
    const result = run([sca('fp-a', 'GHSA-a'), sca('fp-b', 'GHSA-b')], [old]);
    expect(result.stateByFinding.get('SPX-000001')).toBe('EXISTING');
    expect(result.stateByFinding.get('SPX-000002')).toBe('NEW');
  });

  it('does not touch findings that were already resolved in the baseline', () => {
    const result = run([], [prior('SPX-000001', 'fp1', 'RESOLVED')]);
    expect(result.assessments).toHaveLength(0);
  });
});
