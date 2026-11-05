import { join } from 'node:path';
import type { SourceTree } from '@spinxsca/core';
import { GroundTruth } from '@spinxsca/schemas';
import { describe, expect, it } from 'vitest';
import { submitFor, type TriageDeliverable, triageProblems } from '../src/autonomy/deliverables';
import { consistencyIssue } from '../src/autonomy/verdicts';
import { loadPersonas } from '../src/personas/loader';
import { checkManifest, PERSONA_RISK_CEILING } from '../src/personas/manifest';

const ROOT = join(import.meta.dirname, '../../..');
const source: SourceTree = {
  root: '/v',
  listFiles: async () => [],
  readText: async (p) => (p === 'a.ts' ? 'l1\nl2\nl3\nl4\nl5\n' : undefined),
  gitInfo: async () => undefined,
};
const ctx = { source, paths: ['a.ts'] };
const gt = GroundTruth.parse({
  archetype: 'http_api',
  carveouts: [
    {
      carveoutId: 'CO-1',
      pattern: 'admin lists all',
      justification: 'by design',
      evidence: [{ path: 'a.ts', startLine: 1, endLine: 1 }],
    },
  ],
});
const base: TriageDeliverable = {
  handle: 'CF-1',
  verdict: 'FALSE_POSITIVE',
  severity: 'HIGH',
  confidence: 'HIGH',
  rationale: 'The guard at a.ts:2 enforces ownership before the lookup.',
  evidence: [],
  counterevidence: ['a.ts:2 OwnershipGuard checks req.user.id'],
  noiseReason: 'guard not modelled by the rule',
  missingEvidence: [],
  refutationAttempts: [],
};

describe("downgrade-don't-delete validation (ADR-050)", () => {
  it('refuses a refutation that cites nothing and accepts a cited break or a carve-out', async () => {
    const none = await triageProblems(base, { ...ctx, groundTruth: gt });
    expect(none.join('\n')).toContain('cited path:line, or carveoutMatched');
    const cited = await triageProblems(
      { ...base, refutationAttempts: [{ link: 'authz', result: 'broke', evidence: 'a.ts:2 OwnershipGuard holds' }] },
      { ...ctx, groundTruth: gt },
    );
    expect(cited).toEqual([]);
    const badCitation = await triageProblems(
      { ...base, refutationAttempts: [{ link: 'authz', result: 'broke', evidence: 'a.ts:99 nothing there' }] },
      { ...ctx, groundTruth: gt },
    );
    expect(badCitation.join('\n')).toContain('refutation');
    expect(await triageProblems({ ...base, carveoutMatched: 'CO-1' }, { ...ctx, groundTruth: gt })).toEqual([]);
    expect((await triageProblems({ ...base, carveoutMatched: 'CO-7' }, { ...ctx, groundTruth: gt })).join()).toContain(
      'CO-7 is not a carve-out',
    );
    expect(
      (
        await triageProblems(
          { ...base, counterevidence: ['probably fine'], carveoutMatched: 'CO-1' },
          { ...ctx, groundTruth: gt },
        )
      ).join(),
    ).toContain('cite path:line');
  });

  it("requires a HIGH-confidence confirmation to address the reporter's open obligations", async () => {
    const tp: TriageDeliverable = {
      ...base,
      verdict: 'TRUE_POSITIVE',
      evidence: [{ path: 'a.ts', startLine: 2, endLine: 2 }],
      counterevidence: [],
      attackPath: { attacker: 'user', entryPoint: 'e', source: 's', sink: 'k', preconditions: [], controls: [] },
    };
    const problems = await triageProblems(tp, { ...ctx, claim: { proofObligations: ['reachability of the route'] } });
    expect(problems.join()).toContain('proof obligation');
    expect(
      await triageProblems(
        { ...tp, refutationAttempts: [{ link: 'reachability', result: 'held', evidence: 'a.ts:1 route is mounted' }] },
        { ...ctx, claim: { proofObligations: ['reachability'] } },
      ),
    ).toEqual([]);
    expect(
      await triageProblems({ ...tp, confidence: 'MEDIUM' }, { ...ctx, claim: { proofObligations: ['reachability'] } }),
    ).toEqual([]);
  });

  it('flags a verdict that contradicts its own rationale', () => {
    expect(
      consistencyIssue({
        verdict: 'FALSE_POSITIVE',
        confidence: 'HIGH',
        rationale: 'There is no ownership check on this route but the data is public.',
      }),
    ).toContain('FALSE_POSITIVE');
    expect(
      consistencyIssue({
        verdict: 'FALSE_POSITIVE',
        confidence: 'HIGH',
        rationale: 'Unlike the sibling, this route is not missing an ownership check: OwnershipGuard runs first.',
      }),
    ).toBeUndefined();
    expect(
      consistencyIssue({
        verdict: 'TRUE_POSITIVE',
        confidence: 'HIGH',
        rationale: 'I could not confirm the route is reachable without authentication.',
      }),
    ).toContain('HIGH');
    expect(
      consistencyIssue({
        verdict: 'TRUE_POSITIVE',
        confidence: 'MEDIUM',
        rationale: 'I could not confirm reachability.',
      }),
    ).toBeUndefined();
    expect(
      consistencyIssue({ verdict: 'BLOCKED', confidence: 'LOW', rationale: 'no ownership check visible' }),
    ).toBeUndefined();
  });

  it('offers submit_recon and a findings deliverable with coverage rows for logic audits', () => {
    expect(submitFor('RECON', ctx)?.name).toBe('submit_recon');
    expect(submitFor('LOGIC_AUDIT', ctx)?.name).toBe('submit_findings');
    expect(submitFor('COMPLETENESS_CRITIC', ctx)?.name).toBe('submit_findings');
  });
});

describe('phase 6 personas', () => {
  it('load within their risk ceilings', () => {
    const personas = loadPersonas(join(ROOT, 'prompts'));
    for (const id of ['recon', 'logic', 'critic']) {
      const p = personas.get(id);
      expect(p, id).toBeDefined();
      expect(checkManifest(p!.manifest)).toEqual([]);
      expect(p?.prompt).toContain('untrusted');
    }
    expect(PERSONA_RISK_CEILING.critic).toBe('RECORD');
    expect(personas.get('critic')?.manifest.tools).not.toContain('shell_exec');
    expect(personas.get('validator')?.prompt).toContain("Downgrade, don't delete");
    expect(personas.get('logic')?.manifest.skills).toContain('business-logic');
  });
});
