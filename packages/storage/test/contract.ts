import type { ScanRepository } from '@spinxsca/core';
import type { AnalysisManifest, FindingAssessment, ScanRun } from '@spinxsca/schemas';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

const now = '2026-10-29T00:00:00.000Z';
const digest = (c: string) => `sha256:${c.repeat(64)}` as const;

/**
 * Behaviour every ScanRepository adapter must share (SQLite for the CLI, PostgreSQL for the service):
 * the same ordering, idempotency and atomicity guarantees.
 */
export function repositoryContract(
  name: string,
  open: () => Promise<{ repo: ScanRepository; close: () => Promise<void> | void }>,
): void {
  describe(`${name}: repository contract`, () => {
    let repo: ScanRepository;
    let close: () => Promise<void> | void;
    beforeEach(async () => {
      ({ repo, close } = await open());
    });
    afterEach(async () => {
      await close();
    });

    async function seedScan(scanId: string, requestedAt = now): Promise<ScanRun> {
      const { project, repository } = await repo.ensureProject({ name: 'demo', rootPath: '/tmp/demo' });
      await repo.saveSnapshot({
        snapshotId: 'snap_1',
        repositoryId: repository.repositoryId,
        kind: 'WORKSPACE',
        contentManifestDigest: digest('a'),
        fileCount: 1,
        fileListDigest: digest('b'),
        capturedAt: now,
      });
      const manifest = {
        schemaVersion: 1,
        scanId,
        engineVersion: '0.0.0',
        source: { snapshotId: 'snap_1', contentManifestDigest: digest('a') },
        scannerBundle: { digest: digest('c'), scanners: [] },
        ruleBundles: [],
        knowledgeBase: null,
        aiPolicy: { level: 'off', policyVersion: 'x' },
        scanMode: 'FULL',
        scope: { exclude: [] },
        requestedAt,
      } satisfies AnalysisManifest;
      const scan: ScanRun = {
        scanId,
        projectId: project.projectId,
        repositoryId: repository.repositoryId,
        snapshotId: 'snap_1',
        mode: 'FULL',
        status: 'RUNNING',
        manifest,
        manifestDigest: digest('d'),
        requestedAt,
      };
      await repo.createScan(scan);
      return scan;
    }

    it('keeps a single project per state database', async () => {
      const a = await repo.ensureProject({ name: 'demo', rootPath: '/a' });
      const b = await repo.ensureProject({ name: 'other', rootPath: '/b' });
      expect(b.project.projectId).toBe(a.project.projectId);
      expect((await repo.getProject())?.repository.rootPath).toBe('/a');
    });

    it('round-trips scans and finds the latest completed one', async () => {
      const first = await seedScan('scan_01', '2026-10-29T00:00:00.000Z');
      await repo.updateScan(first.scanId, { status: 'COMPLETED', completedAt: now });
      const second = await seedScan('scan_02', '2026-10-29T00:01:00.000Z');
      expect((await repo.getScan(second.scanId))?.manifest.scanId).toBe('scan_02');
      expect((await repo.latestScan(first.projectId, ['COMPLETED']))?.scanId).toBe('scan_01');
      expect(await repo.latestScan(first.projectId, ['COMPLETED'], 'scan_01')).toBeUndefined();
    });

    it('upserts tasks and finds reusable output by idempotency key', async () => {
      await seedScan('scan_01');
      const task = {
        taskId: 'task_1',
        scanId: 'scan_01',
        kind: 'SCANNER' as const,
        name: 'scanner',
        scannerId: 'semgrep',
        idempotencyKey: 'k1',
        status: 'RUNNING' as const,
        attempt: 1,
      };
      await repo.upsertTask(task);
      expect(await repo.findReusableTask('k1')).toBeUndefined();
      await repo.upsertTask({ ...task, status: 'SUCCEEDED', outputDigest: digest('e') });
      expect((await repo.findReusableTask('k1'))?.outputDigest).toBe(digest('e'));
      expect(await repo.listTasks('scan_01')).toHaveLength(1);
    });

    it('commits reconciliation atomically and reports the latest state per finding', async () => {
      const scan = await seedScan('scan_01');
      const assessment: FindingAssessment = {
        assessmentId: 'asm_1',
        findingId: 'SPX-000001',
        scanId: scan.scanId,
        occurrenceId: 'occ_1',
        reconciliationState: 'NEW',
        classification: 'POTENTIAL',
        severity: 'HIGH',
        confidence: 'MEDIUM',
        exploitability: 'UNKNOWN',
        verificationLevel: 'L1_STATIC',
        evidenceIds: [],
        counterevidence: [],
        missingEvidence: [],
        reasoningSummary: 'r',
        changeCauses: ['FIRST_SCAN'],
        assessedBy: 'host',
        assessedAt: now,
      };
      await repo.commitReconciliation(scan.scanId, {
        newFindings: [
          {
            findingId: 'SPX-000001',
            projectId: scan.projectId,
            seq: 1,
            category: 'SQL_INJECTION',
            ruleFamily: 'sqli',
            title: 'SQL injection',
            cwe: ['CWE-89'],
            canonicalFingerprint: 'fp1',
            fingerprintAlgorithm: 'spinxsca/fp/v1',
            firstSeenScanId: scan.scanId,
            createdAt: now,
          },
        ],
        fingerprintAliases: [{ findingId: 'SPX-000001', fingerprint: 'fp-alias', algorithm: 'spinxsca/fp/v1' }],
        occurrences: [
          {
            occurrenceId: 'occ_1',
            findingId: 'SPX-000001',
            scanId: scan.scanId,
            snapshotId: 'snap_1',
            locations: [{ path: 'a.js', startLine: 1, endLine: 1, role: 'primary' }],
            fingerprint: 'fp1',
            anchor: { path: 'a.js', symbol: '', shape: 's', instance: 0 },
            ruleIds: ['r1'],
            candidateIds: ['c1'],
            evidenceIds: [],
          },
        ],
        assessments: [assessment],
        matchEvents: [],
      });
      expect(await repo.nextFindingSeq(scan.projectId)).toBe(2);
      expect(Object.fromEntries(await repo.fingerprintIndex(scan.projectId))).toEqual({
        fp1: 'SPX-000001',
        'fp-alias': 'SPX-000001',
      });
      const latest = (await repo.latestByFinding(scan.projectId)).get('SPX-000001');
      expect(latest?.assessment?.reconciliationState).toBe('NEW');
      expect(latest?.occurrence?.occurrenceId).toBe('occ_1');
      await expect(
        repo.commitReconciliation(scan.scanId, {
          newFindings: [],
          fingerprintAliases: [],
          occurrences: [],
          assessments: [assessment],
          matchEvents: [],
        }),
      ).rejects.toThrow();
    });

    it('stores dispositions, baselines with optimistic checks, and agent runs', async () => {
      const scan = await seedScan('scan_01');
      await repo.commitReconciliation(scan.scanId, {
        newFindings: [
          {
            findingId: 'SPX-000001',
            projectId: scan.projectId,
            seq: 1,
            category: 'XSS',
            ruleFamily: 'xss',
            title: 'x',
            cwe: ['CWE-79'],
            canonicalFingerprint: 'fp',
            fingerprintAlgorithm: 'spinxsca/fp/v1',
            firstSeenScanId: scan.scanId,
            createdAt: now,
          },
        ],
        fingerprintAliases: [],
        occurrences: [],
        assessments: [],
        matchEvents: [],
      });
      await repo.saveDisposition({
        dispositionId: 'd1',
        findingId: 'SPX-000001',
        kind: 'FALSE_POSITIVE',
        reason: 'sanitized upstream',
        scope: { type: 'PROJECT', ref: scan.projectId },
        decidedBy: 'dev',
        decidedAt: now,
      });
      expect((await repo.listDispositions(scan.projectId)).map((d) => d.kind)).toEqual(['FALSE_POSITIVE']);

      const base = {
        projectId: scan.projectId,
        scopeType: 'BRANCH' as const,
        scopeRef: 'main',
        scanId: scan.scanId,
        reason: 'r',
      };
      await repo.activateBaseline({ ...base, baselineId: 'b1', activatedAt: '2026-10-29T00:00:00.000Z' });
      await expect(
        repo.activateBaseline({ ...base, baselineId: 'b2', activatedAt: '2026-10-29T00:01:00.000Z' }),
      ).rejects.toThrow('changed concurrently');
      await repo.activateBaseline({ ...base, baselineId: 'b2', activatedAt: '2026-10-29T00:01:00.000Z' }, 'b1');
      expect((await repo.activeBaseline(scan.projectId, 'BRANCH', 'main'))?.baselineId).toBe('b2');
      expect((await repo.listBaselines(scan.projectId)).map((b) => [b.baselineId, Boolean(b.deactivatedAt)])).toEqual([
        ['b2', false],
        ['b1', true],
      ]);

      const run = {
        agentRunId: 'run1',
        role: 'explain' as const,
        scanId: scan.scanId,
        findingId: 'SPX-000001',
        provider: 'scripted',
        model: 'scripted',
        modelsUsed: ['scripted'],
        promptBundleDigest: 'sha256:x',
        status: 'COMPLETED' as const,
        usage: { inputTokens: 1, outputTokens: 2, cacheReadTokens: 0, cacheWriteTokens: 0 },
        steps: [],
        startedAt: now,
        completedAt: now,
      };
      await repo.saveAgentRun(run);
      await repo.saveAgentRun({ ...run, costUsd: 0.01 });
      const runs = await repo.listAgentRuns({ findingId: 'SPX-000001' });
      expect(runs).toHaveLength(1);
      expect(runs[0]?.costUsd).toBe(0.01);
    });
  });
}
