import type { SourceTree } from '@spinxsca/core';
import { type AiFinding, GroundTruth } from '@spinxsca/schemas';
import { describe, expect, it } from 'vitest';
import {
  closedEndedProblems,
  coverageOf,
  isDuplicate,
  mergeOperatorContext,
  renderGroundTruth,
  sliceFor,
  validateGroundTruth,
} from '../src/ground-truth';

const gt = GroundTruth.parse({
  archetype: 'http_api',
  invariants: [
    {
      invariantId: 'INV-1',
      location: { path: 'orders.controller.ts', startLine: 4, endLine: 5 },
      expected: 'findOne scopes the lookup to the caller',
      howToCheck: 'read findById',
      packets: ['authz-1'],
      familyId: 'FAM-1',
    },
    {
      invariantId: 'INV-2',
      location: { path: 'users.controller.ts', startLine: 9, endLine: 9 },
      expected: 'password reset tokens are single use',
      howToCheck: 'read reset()',
      packets: ['authn-1'],
    },
  ],
  baselines: [
    {
      baselineId: 'BL-1',
      pattern: 'owner-scoped query',
      location: { path: 'orders.service.ts', startLine: 2, endLine: 2 },
      whyCorrect: 'filters by ownerId',
    },
  ],
  families: [
    {
      familyId: 'FAM-1',
      rootCause: 'order lookups by id',
      baselineId: 'BL-1',
      members: [
        { path: 'orders.controller.ts', startLine: 3, label: 'GET /orders/:id' },
        { path: 'orders.controller.ts', startLine: 8, label: 'DELETE /orders/:id' },
      ],
    },
  ],
  carveouts: [
    {
      carveoutId: 'CO-1',
      pattern: 'admin lists all orders',
      justification: 'admin role by design',
      evidence: [{ path: 'admin.controller.ts', startLine: 2, endLine: 2 }],
    },
  ],
  residualUnknowns: [
    {
      unknownId: 'RQ-1',
      question: 'Is the admin role assignable by tenants?',
      whySourceCannotSettle: 'role catalogue lives in IAM',
      kind: 'role',
      affects: ['INV-2'],
    },
  ],
});

const finding: AiFinding = {
  category: 'BROKEN_OBJECT_LEVEL_AUTHORIZATION',
  cwe: ['CWE-639'],
  title: 'Any user reads any order',
  summary: 's',
  confidence: 'MEDIUM',
  severity: 'HIGH',
  attacker: 'authenticated user',
  invariantViolated: 'ownership',
  claim: 'An authenticated user can read any order.',
  preconditions: [],
  capabilitiesGained: [],
  proofObligations: [],
  threatModelClass: 'real_bug',
  invariantId: 'INV-1',
  familyId: 'FAM-1',
  locations: [{ path: 'orders.controller.ts', startLine: 4, endLine: 5, role: 'primary' }],
  evidence: ['e'],
  counterevidence: [],
  remediation: 'scope by owner',
};

describe('ground truth helpers (ADR-049)', () => {
  it('slices by packet and path, keeping every carve-out and the affected unknowns', () => {
    const slice = sliceFor(gt, { packetIds: ['authz-1'], paths: ['orders.controller.ts'] });
    expect(slice.invariants.map((i) => i.invariantId)).toEqual(['INV-1']);
    expect(slice.families.map((f) => f.familyId)).toEqual(['FAM-1']);
    expect(slice.baselines.map((b) => b.baselineId)).toEqual(['BL-1']);
    expect(slice.carveouts).toHaveLength(1);
    expect(slice.residualUnknowns).toHaveLength(0);
    expect(sliceFor(gt, { invariantIds: ['INV-2'] }).residualUnknowns.map((u) => u.unknownId)).toEqual(['RQ-1']);
    expect(sliceFor(gt, {})).toBe(gt);
  });

  it('renders the four sections inside an untrusted block and honours the cap', () => {
    const text = renderGroundTruth(gt);
    expect(text.startsWith('<ground_truth untrusted="true" source="recon">')).toBe(true);
    for (const needle of ['INV-1 @ orders.controller.ts:4-5', 'BL-1', 'FAM-1', 'CO-1', 'RQ-1'])
      expect(text).toContain(needle);
    expect(renderGroundTruth(gt, { sections: ['carveouts'] })).not.toContain('INV-1');
    expect(renderGroundTruth(gt, { maxChars: 300 })).toContain('truncated');
  });

  it('turns coverage gaps into submission problems', () => {
    const slice = sliceFor(gt, { packetIds: ['authz-1'] });
    const ok = closedEndedProblems(
      {
        findings: [finding],
        invariantResults: [{ invariantId: 'INV-1', result: 'FAIL', evidence: [], note: '' }],
        variantLog: [
          {
            familyId: 'FAM-1',
            member: { path: 'orders.controller.ts', startLine: 3 },
            verdict: 'VULNERABLE',
            note: '',
          },
          { familyId: 'FAM-1', member: { path: 'orders.controller.ts', startLine: 8 }, verdict: 'SAFE', note: '' },
        ],
        deferred: [],
      },
      slice,
    );
    expect(ok).toEqual([]);
    const problems = closedEndedProblems(
      {
        findings: [{ ...finding, invariantId: undefined, confidence: 'HIGH', proofObligations: ['reachability'] }],
        invariantResults: [
          { invariantId: 'INV-1', result: 'FAIL', evidence: [], note: '' },
          { invariantId: 'INV-2', result: 'UNKNOWN', evidence: [], note: '' },
        ],
        variantLog: [
          {
            familyId: 'FAM-1',
            member: { path: 'orders.controller.ts', startLine: 8 },
            verdict: 'VULNERABLE',
            note: '',
          },
        ],
        deferred: [],
      },
      slice,
    );
    expect(problems.join('\n')).toContain('INV-1 is FAIL but no finding');
    expect(problems.join('\n')).toContain('INV-2, which is not in your slice');
    expect(problems.join('\n')).toContain('UNKNOWN without a note');
    expect(problems.join('\n')).toContain('orders.controller.ts:8 is VULNERABLE but no finding');
    expect(problems.join('\n')).toContain('HIGH confidence but open proof obligations');
    expect(
      closedEndedProblems(
        {
          findings: [{ ...finding, threatModelClass: 'by_design' }],
          invariantResults: [],
          variantLog: [],
          deferred: [],
        },
        slice,
      ).join(),
    ).toContain('by_design');
    expect(
      closedEndedProblems({ findings: [], invariantResults: [], variantLog: [], deferred: [] }, slice, {
        strict: true,
      }).join(),
    ).toContain('INV-1 has no result');
  });

  it('computes coverage and dedupes overlapping findings', () => {
    const coverage = coverageOf(gt, [
      { invariantResults: [{ invariantId: 'INV-1', result: 'PASS', evidence: [], note: '' }], variantLog: [] },
    ]);
    expect(coverage).toEqual({
      invariantGaps: ['INV-2'],
      invariantTotal: 2,
      memberGaps: ['FAM-1 orders.controller.ts:3', 'FAM-1 orders.controller.ts:8'],
      memberTotal: 2,
    });
    expect(
      isDuplicate(finding, {
        ...finding,
        title: 'Different words',
        locations: [{ path: 'orders.controller.ts', startLine: 6, endLine: 6, role: 'primary' }],
      }),
    ).toBe(true);
    expect(
      isDuplicate(finding, {
        ...finding,
        locations: [{ path: 'orders.controller.ts', startLine: 20, endLine: 20, role: 'primary' }],
      }),
    ).toBe(false);
    expect(isDuplicate(finding, { ...finding, category: 'SQL_INJECTION' })).toBe(false);
  });

  it('folds operator context into carve-outs and trust claims', () => {
    const merged = mergeOperatorContext(gt, {
      accepted_risks: ['Admins may export every tenant for billing.'],
      roles: [{ name: 'admin', trust: 'manages all tenants', provenance: 'role catalogue v2' }],
      trust_claims: [{ statement: 'The gateway authenticates every route.', provenance: 'AR-17' }],
      business_invariants: [],
    });
    expect(merged.carveouts.map((c) => c.carveoutId)).toEqual(['CO-1', 'CO-900']);
    expect(merged.carveouts[1]?.source).toBe('operator');
    expect(merged.trustClaims.map((c) => c.confidence)).toEqual(['claimed', 'claimed']);
  });

  it('rejects ground truth that cites lines outside the snapshot', async () => {
    const source: SourceTree = {
      root: '/v',
      listFiles: async () => [],
      readText: async (p) => (p === 'orders.controller.ts' ? 'a\nb\nc\nd\ne\nf\ng\nh\n' : undefined),
      gitInfo: async () => undefined,
    };
    const problems = await validateGroundTruth(
      gt,
      { source, paths: ['orders.controller.ts'] },
      { packetIds: new Set(['authz-1']) },
    );
    expect(problems.some((p) => p.includes('users.controller.ts'))).toBe(true);
    expect(problems.some((p) => p.includes('unknown packet authn-1'))).toBe(true);
    const carveoutNoEvidence = { ...gt, carveouts: [{ ...gt.carveouts[0]!, evidence: [] }] };
    expect((await validateGroundTruth(carveoutNoEvidence, { source, paths: [] })).join()).toContain(
      'CO-1 needs at least one evidence',
    );
  });
});
