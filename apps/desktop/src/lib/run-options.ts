import type { AutonomyMode, ReviewDefaults, ReviewRunOptions } from '../api/types';

/**
 * The "before you start" form of a review, as the user edits it. Numbers stay strings while typed;
 * `toRequest` turns the draft into the API body and sends only what differs from the service
 * defaults, so a review started with untouched options behaves exactly like one started from the CLI.
 */
export interface RunOptionsDraft {
  /** One objective per line. */
  objectives: string;
  mode: AutonomyMode;
  maxCostUsd: string;
  maxRounds: string;
  maxWallClockMin: string;
  l3: boolean;
  recon: boolean;
  criticPasses: number;
  scanners: string[];
  /** One intended behaviour per line. */
  acceptedRisks: string;
}

export const MODES: ReadonlyArray<{ value: AutonomyMode; label: string; description: string }> = [
  {
    value: 'observe',
    label: 'Observe',
    description: 'Reads and reports only. Nothing runs in a sandbox and nothing is written.',
  },
  {
    value: 'supervised',
    label: 'Supervised',
    description: 'Asks you before anything runs your code or writes outside the case.',
  },
  {
    value: 'autonomous',
    label: 'Autonomous',
    description: 'Lets the reviewer model approve low-risk actions; repository changes still need you.',
  },
];
const MODE_RANK: Readonly<Record<AutonomyMode, number>> = { observe: 0, supervised: 1, autonomous: 2 };

/** Modes the service allows: the configured one and every stricter one. */
export const allowedModes = (defaults: Pick<ReviewDefaults, 'mode'>) =>
  MODES.filter((m) => MODE_RANK[m.value] <= MODE_RANK[defaults.mode]);

export const SCANNER_LABELS: Readonly<Record<string, { label: string; description: string }>> = {
  semgrep: { label: 'Semgrep', description: 'Code patterns (injection, traversal, SSRF…)' },
  'osv-scanner': { label: 'OSV', description: 'Vulnerable dependencies' },
  gitleaks: { label: 'Gitleaks', description: 'Secrets in files and git history' },
  trivy: { label: 'Trivy', description: 'Dockerfile and infrastructure configuration' },
};

const lines = (text: string) =>
  text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

export function draftFrom(defaults: ReviewDefaults, saved?: Partial<RunOptionsDraft>): RunOptionsDraft {
  const base: RunOptionsDraft = {
    objectives: '',
    mode: defaults.mode,
    maxCostUsd: String(defaults.maxCostUsd),
    maxRounds: String(defaults.maxRounds),
    maxWallClockMin: String(defaults.maxWallClockMin),
    l3: defaults.l3,
    recon: defaults.recon,
    criticPasses: defaults.criticPasses,
    scanners: [...defaults.scanners],
    acceptedRisks: '',
  };
  if (!saved) return base;
  const merged = { ...base, ...saved };
  // A saved draft never widens what the service allows today.
  return {
    ...merged,
    mode: MODE_RANK[merged.mode] <= MODE_RANK[defaults.mode] ? merged.mode : defaults.mode,
    scanners: merged.scanners.filter((s) => defaults.scanners.includes(s)),
  };
}

export interface DraftProblem {
  field: keyof RunOptionsDraft;
  message: string;
}

/** Objectives are sent even when the service reports no options (one per line). */
export function objectiveProblems(text: string): DraftProblem[] {
  const objectives = lines(text);
  const problems: DraftProblem[] = [];
  if (objectives.length > 10) problems.push({ field: 'objectives', message: 'At most 10 objectives.' });
  if (objectives.some((o) => o.length < 5 || o.length > 400))
    problems.push({ field: 'objectives', message: 'Each objective needs 5 to 400 characters.' });
  return problems;
}

export const objectiveList = lines;

/** Problems that would make the service reject the request, phrased for the form. */
export function validateDraft(d: RunOptionsDraft, defaults: ReviewDefaults): DraftProblem[] {
  const problems: DraftProblem[] = [];
  const number = (
    field: 'maxCostUsd' | 'maxRounds' | 'maxWallClockMin',
    ceiling: number,
    unit: string,
    integer: boolean,
  ) => {
    const raw = d[field].trim();
    const n = Number(raw);
    if (raw === '' || !Number.isFinite(n) || n <= 0) problems.push({ field, message: `Enter a positive ${unit}.` });
    else if (integer && !Number.isInteger(n)) problems.push({ field, message: `Enter a whole number of ${unit}.` });
    else if (n > ceiling) problems.push({ field, message: `At most ${ceiling} ${unit} on this service.` });
  };
  number('maxCostUsd', defaults.maxCostUsd, 'USD', false);
  number('maxRounds', defaults.maxRounds, 'rounds', true);
  number('maxWallClockMin', defaults.maxWallClockMin, 'minutes', true);
  if (d.scanners.length === 0) problems.push({ field: 'scanners', message: 'Choose at least one scanner.' });
  problems.push(...objectiveProblems(d.objectives));
  const risks = lines(d.acceptedRisks);
  if (risks.length > 30) problems.push({ field: 'acceptedRisks', message: 'At most 30 entries.' });
  if (risks.some((r) => r.length < 10 || r.length > 600))
    problems.push({ field: 'acceptedRisks', message: 'Describe each behaviour in 10 to 600 characters.' });
  return problems;
}

/** The API body: objectives plus only the options that differ from the service defaults. */
export function toRequest(
  d: RunOptionsDraft,
  defaults: ReviewDefaults | undefined,
): { objectives?: string[]; options?: ReviewRunOptions } {
  const objectives = lines(d.objectives);
  const out: { objectives?: string[]; options?: ReviewRunOptions } = objectives.length ? { objectives } : {};
  if (!defaults?.available) return out;
  const options: ReviewRunOptions = {};
  if (d.mode !== defaults.mode) options.mode = d.mode;
  const cost = Number(d.maxCostUsd);
  if (cost !== defaults.maxCostUsd) options.maxCostUsd = cost;
  const rounds = Number(d.maxRounds);
  if (rounds !== defaults.maxRounds) options.maxRounds = rounds;
  const minutes = Number(d.maxWallClockMin);
  if (minutes !== defaults.maxWallClockMin) options.maxWallClockMin = minutes;
  if (d.l3 !== defaults.l3) options.l3 = d.l3;
  if (d.recon !== defaults.recon) options.recon = d.recon;
  if (d.recon && d.criticPasses !== defaults.criticPasses) options.criticPasses = d.criticPasses;
  const sameScanners =
    d.scanners.length === defaults.scanners.length && d.scanners.every((s) => defaults.scanners.includes(s));
  if (!sameScanners) options.scanners = defaults.scanners.filter((s) => d.scanners.includes(s));
  const risks = lines(d.acceptedRisks);
  if (risks.length) options.acceptedRisks = risks;
  return Object.keys(options).length ? { ...out, options } : out;
}

/** One line describing the options, shown while the options panel is collapsed. */
export function summarize(d: RunOptionsDraft, defaults: ReviewDefaults): string {
  const mode = MODES.find((m) => m.value === d.mode)?.label ?? d.mode;
  const parts = [
    mode,
    `up to $${Number(d.maxCostUsd) || defaults.maxCostUsd}`,
    `${Number(d.maxRounds) || defaults.maxRounds} rounds`,
    `${Number(d.maxWallClockMin) || defaults.maxWallClockMin} min`,
    d.scanners.length === defaults.scanners.length
      ? 'all scanners'
      : `${d.scanners.length} of ${defaults.scanners.length} scanners`,
    d.recon ? 'logic analysis' : 'no logic analysis',
  ];
  if (d.l3) parts.push('proofs of concept');
  return parts.join(' · ');
}

/** True when the draft would send no option at all. */
export const isDefault = (d: RunOptionsDraft, defaults: ReviewDefaults) =>
  !toRequest({ ...d, objectives: '' }, defaults).options;

const storageKey = (projectId: string) => `spinxsca.reviewOptions.${projectId}`;

/** Options remembered for a project on this computer; storage may be unavailable, which is fine. */
export function loadSavedDraft(projectId: string): Partial<RunOptionsDraft> | undefined {
  try {
    const raw = globalThis.localStorage?.getItem(storageKey(projectId));
    return raw ? (JSON.parse(raw) as Partial<RunOptionsDraft>) : undefined;
  } catch {
    return undefined;
  }
}

export function saveDraft(projectId: string, draft: RunOptionsDraft | undefined): void {
  try {
    if (draft) globalThis.localStorage?.setItem(storageKey(projectId), JSON.stringify(draft));
    else globalThis.localStorage?.removeItem(storageKey(projectId));
  } catch {
    // Remembering options is a convenience; the review starts either way.
  }
}
