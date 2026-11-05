import { cpSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { AgentInvestigator, loadPromptBundle, scriptedLogicProvider } from '@spinxsca/agent';
import { buildReportModel, evaluatePolicy, type Investigator, runScan, silentLogger } from '@spinxsca/core';
import { afterEach, describe, expect, it } from 'vitest';
import { openEngine, scanDeps } from '../src/engine';

const ROOT = resolve(__dirname, '../../..');
const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

/**
 * Phase 6 (ADR-049/050): recon-first investigation on a copy of the IDOR reference case, with the
 * scripted logic provider (no model, no Docker scanner). The census flags GET /orders/:id as the
 * sibling without an ownership scope; the scripted roles turn that into one BOLA draft that the
 * host records as AI-discovered and the gate exempts until it is validated.
 */
describe('phase 6: recon-first logic analysis (scripted)', () => {
  it('finds the IDOR reference case, labels it AI-discovered and gates it by classification', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'spx-p6-'));
    dirs.push(dir);
    cpSync(join(ROOT, 'evals/internal/003-idor-nest/src'), join(dir, 'src'), { recursive: true });
    rmSync(join(dir, 'src/.spinxsca'), { recursive: true, force: true });
    const engine = openEngine({
      scanRoot: join(dir, 'src'),
      stateDir: join(dir, 'state'),
      kbDir: join(dir, 'kb'),
      logger: silentLogger,
    });
    engine.scanners.splice(0, engine.scanners.length);
    const investigator: Investigator = new AgentInvestigator({
      provider: scriptedLogicProvider,
      prompts: loadPromptBundle(join(ROOT, 'prompts')),
    });
    try {
      const outcome = await runScan(
        { ...scanDeps(engine), investigator },
        {
          projectName: 't',
          mode: 'FULL',
          exclude: [],
          baseline: { kind: 'none' },
          reuseCache: false,
          ai: { level: 'standard', maxFindings: 0, maxCostUsd: 1 },
        },
      );
      expect(outcome.ai?.investigated).toBe(1);
      expect(outcome.ai?.groundTruthDigest).toMatch(/^sha256:/);
      expect(outcome.ai?.coverage).toMatchObject({ invariantGaps: [], invariantTotal: 1 });
      const model = await buildReportModel(engine.repo, outcome.scan.scanId);
      expect(model.present).toHaveLength(1);
      const entry = model.present[0];
      expect(entry?.finding.category).toBe('BROKEN_OBJECT_LEVEL_AUTHORIZATION');
      const loc = entry?.occurrence?.locations[0];
      expect(loc?.path).toBe('orders/orders.controller.ts');
      expect(loc?.startLine).toBeGreaterThanOrEqual(9);
      expect(loc?.startLine).toBeLessThanOrEqual(13);
      const assessment = outcome.assessments[0];
      expect(assessment?.discoveredBy).toBe('ai');
      expect(assessment?.assessedBy).toBe('agent:discovery/ai');
      expect(assessment?.classification).toBe('POTENTIAL');
      expect(evaluatePolicy(outcome.assessments, { failOnSeverity: 'HIGH', newFindingsOnly: true }).passed).toBe(true);
      expect(
        evaluatePolicy(outcome.assessments, {
          failOnSeverity: 'HIGH',
          newFindingsOnly: true,
          aiDiscoveredMinClassification: 'POTENTIAL',
        }).passed,
      ).toBe(false);
      const roles = (await engine.repo.listAgentRuns({ scanId: outcome.scan.scanId })).map((r) => r.role);
      expect([...roles].sort()).toEqual(['auditor', 'critic', 'investigator', 'recon']);
    } finally {
      engine.close();
    }
  }, 120_000);
});

describe('phase 6: logic evaluation suite (scripted)', () => {
  it('passes the logic suite thresholds with the scripted provider and keeps live-only cases pending', async () => {
    const { runSuite } = await import('../src/eval/harness');
    const result = await runSuite({
      suiteDir: join(ROOT, 'evals/logic'),
      stability: false,
      logger: silentLogger,
      ai: { provider: 'scripted', effort: 'high', refusalFallback: 'default', maxCostUsdPerFinding: 1 },
      aiLevel: 'standard',
    });
    const byId = new Map(result.cases.map((c) => [c.id, c]));
    expect(result.cases.map((c) => c.error).filter(Boolean)).toEqual([]);
    for (const id of [
      '101-idor-sibling-express',
      '104-tenant-isolation-express',
      '109-correct-sibling-baseline-spring',
    ]) {
      expect(byId.get(id)?.grade?.truePositives.length, id).toBe(1);
      expect(byId.get(id)?.grade?.falsePositives.length, id).toBe(0);
    }
    for (const id of ['102-authz-control-exists-nest', '103-admin-by-design-express'])
      expect(byId.get(id)?.grade?.falsePositives.length, id).toBe(0);
    for (const id of [
      '105-refund-race-express',
      '106-mass-assignment-nest',
      '107-workflow-state-bypass-flask',
      '108-fail-open-auth-express',
    ]) {
      expect(byId.get(id)?.grade?.pending.length, id).toBe(1);
      expect(byId.get(id)?.grade?.falseNegatives.length, id).toBe(0);
    }
    expect(result.layers.ai?.truePositives).toBe(3);
    expect(result.siblingSweepRecall).toBe(1);
    expect(result.invariantCoverage).toBe(1);
    expect(result.failures).toEqual([]);
    expect(result.passed).toBe(true);
  }, 300_000);
});
