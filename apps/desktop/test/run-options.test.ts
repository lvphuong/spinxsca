import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ReviewDefaults } from '../src/api/types';
import { resumeJobFor } from '../src/lib/format';
import {
  allowedModes,
  draftFrom,
  isDefault,
  loadSavedDraft,
  saveDraft,
  summarize,
  toRequest,
  validateDraft,
} from '../src/lib/run-options';

const defaults: ReviewDefaults = {
  available: true,
  mode: 'supervised',
  maxCostUsd: 10,
  maxRounds: 6,
  maxWallClockMin: 90,
  l3: false,
  recon: true,
  criticPasses: 1,
  scanners: ['semgrep', 'osv-scanner', 'gitleaks', 'trivy'],
};

// The suite also runs under the repository's node environment, which has no localStorage.
beforeEach(() => {
  const store = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
    clear: () => store.clear(),
  });
});
afterEach(() => vi.unstubAllGlobals());

describe('review run options', () => {
  it('sends nothing but objectives when the options are untouched', () => {
    const d = draftFrom(defaults);
    expect(isDefault(d, defaults)).toBe(true);
    expect(toRequest(d, defaults)).toEqual({});
    expect(toRequest({ ...d, objectives: 'Every admin route is guarded\n\n  ' }, defaults)).toEqual({
      objectives: ['Every admin route is guarded'],
    });
  });

  it('sends only what differs from the service defaults', () => {
    const d = {
      ...draftFrom(defaults),
      mode: 'observe' as const,
      maxCostUsd: '2.5',
      recon: false,
      criticPasses: 2,
      scanners: ['gitleaks', 'semgrep'],
      acceptedRisks: 'Admins can export every tenant for billing.',
    };
    expect(toRequest(d, defaults)).toEqual({
      options: {
        mode: 'observe',
        maxCostUsd: 2.5,
        recon: false,
        // In the service's order; critic passes only count while recon is on.
        scanners: ['semgrep', 'gitleaks'],
        acceptedRisks: ['Admins can export every tenant for billing.'],
      },
    });
    expect(summarize(d, defaults)).toBe(
      'Observe · up to $2.5 · 6 rounds · 90 min · 2 of 4 scanners · no logic analysis',
    );
    expect(toRequest(d, undefined)).toEqual({});
  });

  it('rejects values the service would refuse', () => {
    const d = draftFrom(defaults);
    const problems = validateDraft(
      {
        ...d,
        maxCostUsd: '50',
        maxRounds: '2.5',
        maxWallClockMin: '',
        scanners: [],
        objectives: 'ok',
        acceptedRisks: 'short',
      },
      defaults,
    );
    expect(Object.fromEntries(problems.map((p) => [p.field, p.message]))).toEqual({
      maxCostUsd: 'At most 10 USD on this service.',
      maxRounds: 'Enter a whole number of rounds.',
      maxWallClockMin: 'Enter a positive minutes.',
      scanners: 'Choose at least one scanner.',
      objectives: 'Each objective needs 5 to 400 characters.',
      acceptedRisks: 'Describe each behaviour in 10 to 600 characters.',
    });
    expect(validateDraft(d, defaults)).toEqual([]);
  });

  it('never offers or restores a mode looser than the service allows', () => {
    expect(allowedModes(defaults).map((m) => m.value)).toEqual(['observe', 'supervised']);
    expect(draftFrom(defaults, { mode: 'autonomous', scanners: ['semgrep', 'retired-scanner'] })).toMatchObject({
      mode: 'supervised',
      scanners: ['semgrep'],
    });
  });

  it('remembers options per project and forgets them on request', () => {
    const d = { ...draftFrom(defaults), maxRounds: '3' };
    saveDraft('prj_1', d);
    expect(loadSavedDraft('prj_1')).toEqual(d);
    expect(loadSavedDraft('prj_2')).toBeUndefined();
    saveDraft('prj_1', undefined);
    expect(loadSavedDraft('prj_1')).toBeUndefined();
  });

  it('finds the job that resumes a case', () => {
    const job = (o: object) =>
      ({
        jobId: 'j',
        kind: 'CASE_RESUME',
        payload: { caseId: 'case_1' },
        status: 'QUEUED',
        attempts: 0,
        maxAttempts: 3,
        createdAt: '',
        updatedAt: '',
        ...o,
      }) as never;
    expect(resumeJobFor([job({})], 'case_1')).toBeDefined();
    expect(resumeJobFor([job({ status: 'CANCELLED' })], 'case_1')).toBeUndefined();
    expect(resumeJobFor([job({ payload: { caseId: 'case_2' } })], 'case_1')).toBeUndefined();
  });
});
