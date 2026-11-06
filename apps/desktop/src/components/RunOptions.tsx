import { useId, useState } from 'react';
import type { ReviewDefaults } from '../api/types';
import {
  allowedModes,
  type DraftProblem,
  draftFrom,
  isDefault,
  type RunOptionsDraft,
  SCANNER_LABELS,
  summarize,
} from '../lib/run-options';
import { Icon } from './icons';

/**
 * Options of a review chosen before it starts: scope, analysis, autonomy and limits. The service
 * reports its defaults and ceilings; the form never offers more than they allow.
 */
export function RunOptions({
  defaults,
  draft,
  problems,
  remember,
  onChange,
  onRemember,
}: {
  defaults: ReviewDefaults;
  draft: RunOptionsDraft;
  problems: DraftProblem[];
  remember: boolean;
  onChange: (draft: RunOptionsDraft) => void;
  onRemember: (remember: boolean) => void;
}) {
  const [open, setOpen] = useState(problems.length > 0);
  const id = useId();
  const set = <K extends keyof RunOptionsDraft>(key: K, value: RunOptionsDraft[K]) => onChange({ ...draft, [key]: value });
  const problemOf = (field: keyof RunOptionsDraft) => problems.find((p) => p.field === field)?.message;
  const changed = !isDefault(draft, defaults);
  const toggleScanner = (s: string) =>
    set('scanners', draft.scanners.includes(s) ? draft.scanners.filter((x) => x !== s) : [...draft.scanners, s]);
  const panel = `${id}-panel`;
  const showOpen = open || problems.some((p) => p.field !== 'objectives');

  return (
    <div className={showOpen ? 'run-options open' : 'run-options'}>
      <button type="button" className="run-options-toggle" aria-expanded={showOpen} aria-controls={panel} onClick={() => setOpen(!showOpen)}>
        <Icon name="sliders" size={15} />
        <span className="run-options-title">Run options</span>
        {changed && <span className="run-options-badge">Changed</span>}
        <span className="run-options-summary">{summarize(draft, defaults)}</span>
        <Icon name="chevronDown" size={15} className="run-options-chevron" />
      </button>
      {showOpen && (
        <div className="run-options-body" id={panel}>
          <fieldset className="option-group">
            <legend>Analysis</legend>
            <label className="check">
              <input type="checkbox" checked={draft.recon} onChange={(e) => set('recon', e.target.checked)} />
              <span>
                <span className="check-label">Business logic and authorization analysis</span>
                <span className="field-hint">
                  Maps what the code must guarantee before hunting, then checks every sibling route against it.
                </span>
              </span>
            </label>
            <label className="field field-inline">
              <span className="field-label">Completeness re-passes</span>
              <select
                value={draft.criticPasses}
                disabled={!draft.recon}
                onChange={(e) => set('criticPasses', Number(e.target.value))}
              >
                <option value={0}>None</option>
                <option value={1}>One</option>
                <option value={2}>Two</option>
              </select>
            </label>
            <label className="check">
              <input type="checkbox" checked={draft.l3} onChange={(e) => set('l3', e.target.checked)} />
              <span>
                <span className="check-label">Prove confirmed findings in the sandbox</span>
                <span className="field-hint">
                  Writes a proof of concept for runtime-verifiable findings and runs it without network access. Each
                  run still asks you unless the service allows it.
                </span>
              </span>
            </label>
          </fieldset>

          <fieldset className="option-group">
            <legend>Scanners</legend>
            <div className="check-grid">
              {defaults.scanners.map((s) => (
                <label key={s} className="check">
                  <input type="checkbox" checked={draft.scanners.includes(s)} onChange={() => toggleScanner(s)} />
                  <span>
                    <span className="check-label">{SCANNER_LABELS[s]?.label ?? s}</span>
                    {SCANNER_LABELS[s] && <span className="field-hint">{SCANNER_LABELS[s].description}</span>}
                  </span>
                </label>
              ))}
            </div>
            {problemOf('scanners') && <p className="field-error">{problemOf('scanners')}</p>}
          </fieldset>

          <fieldset className="option-group">
            <legend>Autonomy</legend>
            <div className="choice-list" role="radiogroup" aria-label="Autonomy">
              {allowedModes(defaults).map((m) => (
                <label key={m.value} className={draft.mode === m.value ? 'choice active' : 'choice'}>
                  <input type="radio" name={`${id}-mode`} value={m.value} checked={draft.mode === m.value} onChange={() => set('mode', m.value)} />
                  <span>
                    <span className="check-label">{m.label}</span>
                    <span className="field-hint">{m.description}</span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>

          <fieldset className="option-group">
            <legend>Limits</legend>
            <div className="limits-grid">
              <label className="field">
                <span className="field-label">Budget (USD)</span>
                <input
                  type="number"
                  inputMode="decimal"
                  min={0.01}
                  step={0.5}
                  max={defaults.maxCostUsd}
                  value={draft.maxCostUsd}
                  aria-invalid={Boolean(problemOf('maxCostUsd'))}
                  onChange={(e) => set('maxCostUsd', e.target.value)}
                />
                <span className={problemOf('maxCostUsd') ? 'field-error-inline' : 'field-hint'}>
                  {problemOf('maxCostUsd') ?? `Up to $${defaults.maxCostUsd}`}
                </span>
              </label>
              <label className="field">
                <span className="field-label">Rounds</span>
                <input
                  type="number"
                  min={1}
                  step={1}
                  max={defaults.maxRounds}
                  value={draft.maxRounds}
                  aria-invalid={Boolean(problemOf('maxRounds'))}
                  onChange={(e) => set('maxRounds', e.target.value)}
                />
                <span className={problemOf('maxRounds') ? 'field-error-inline' : 'field-hint'}>
                  {problemOf('maxRounds') ?? `Up to ${defaults.maxRounds}`}
                </span>
              </label>
              <label className="field">
                <span className="field-label">Time limit (minutes)</span>
                <input
                  type="number"
                  min={1}
                  step={5}
                  max={defaults.maxWallClockMin}
                  value={draft.maxWallClockMin}
                  aria-invalid={Boolean(problemOf('maxWallClockMin'))}
                  onChange={(e) => set('maxWallClockMin', e.target.value)}
                />
                <span className={problemOf('maxWallClockMin') ? 'field-error-inline' : 'field-hint'}>
                  {problemOf('maxWallClockMin') ?? `Up to ${defaults.maxWallClockMin}`}
                </span>
              </label>
            </div>
            <p className="field-hint">
              The review stops at whichever limit comes first and keeps what it found. Ceilings come from the service
              configuration.
            </p>
          </fieldset>

          <fieldset className="option-group">
            <legend>Known intended behaviour</legend>
            <label className="field">
              <span className="field-label">Behaviour that looks risky but is intended (one per line)</span>
              <textarea
                rows={2}
                value={draft.acceptedRisks}
                aria-invalid={Boolean(problemOf('acceptedRisks'))}
                onChange={(e) => set('acceptedRisks', e.target.value)}
                placeholder="e.g. Administrators can read every tenant's invoices for billing."
              />
              {problemOf('acceptedRisks') && <span className="field-error-inline">{problemOf('acceptedRisks')}</span>}
            </label>
          </fieldset>

          <div className="run-options-foot">
            <label className="check check-compact">
              <input type="checkbox" checked={remember} onChange={(e) => onRemember(e.target.checked)} />
              <span className="check-label">Remember for this project</span>
            </label>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              disabled={!changed}
              onClick={() => onChange({ ...draftFrom(defaults), objectives: draft.objectives })}
            >
              <Icon name="refresh" size={13} />
              Reset to defaults
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
