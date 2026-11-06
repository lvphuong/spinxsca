import { useCallback, useState } from 'react';
import { type ApiClient, ApiError } from '../api/client';
import type { CaseControlAction } from '../api/types';
import { Icon } from './icons';
import { Spinner, useToast } from './ui';

export type Pending = CaseControlAction | undefined;

/**
 * Pause, resume and stop buttons of one review. Stopping asks for a confirmation inline (the desktop
 * webview has no reliable `window.confirm`). While a request is on its way, or a run is winding down
 * after it, the buttons show what is happening instead of offering the same action twice.
 */
export function RunControls({
  status,
  resuming,
  pending,
  onAction,
  compact,
}: {
  status: string;
  /** A resume job is queued or running for this case. */
  resuming: boolean;
  pending: Pending;
  onAction: (action: CaseControlAction) => void;
  compact?: boolean;
}) {
  const [confirming, setConfirming] = useState(false);
  const size = compact ? 'btn btn-sm' : 'btn';
  const busy = pending !== undefined;
  const canPause = status === 'RUNNING';
  const canResume = status === 'PAUSED' && !resuming;
  const canStop = status === 'RUNNING' || status === 'PARKED' || status === 'PAUSED';
  if (!canPause && !canResume && !canStop && !resuming) return null;

  if (confirming) {
    return (
      <div className="run-controls confirming" role="group" aria-label="Confirm stopping the review">
        <span className="run-controls-question">Stop this review? Findings so far are kept; it cannot be resumed.</span>
        <button
          type="button"
          className={`${size} btn-danger`}
          onClick={() => {
            setConfirming(false);
            onAction('cancel');
          }}
        >
          <Icon name="stop" size={13} />
          Stop review
        </button>
        <button type="button" className={`${size} btn-ghost`} onClick={() => setConfirming(false)}>
          Keep it
        </button>
      </div>
    );
  }

  return (
    <div className="run-controls" role="group" aria-label="Review controls">
      {pending === 'pause' || pending === 'cancel' ? (
        <span className="run-controls-state">
          <Spinner size={13} />
          {pending === 'pause' ? 'Pausing after the current step…' : 'Stopping…'}
        </span>
      ) : resuming || pending === 'resume' ? (
        <span className="run-controls-state">
          <Spinner size={13} />
          Resuming…
        </span>
      ) : null}
      {canPause && (
        <button type="button" className={size} disabled={busy} onClick={() => onAction('pause')}>
          <Icon name="pause" size={13} />
          Pause
        </button>
      )}
      {canResume && (
        <button type="button" className={`${size} btn-primary`} disabled={busy} onClick={() => onAction('resume')}>
          <Icon name="play" size={13} />
          Resume
        </button>
      )}
      {canStop && (
        <button type="button" className={`${size} btn-danger-outline`} disabled={busy} onClick={() => setConfirming(true)}>
          <Icon name="stop" size={13} />
          Stop
        </button>
      )}
    </div>
  );
}

const SENT: Record<CaseControlAction, string> = {
  pause: 'Pausing. Work in progress is kept and continues when you resume.',
  resume: 'Resuming. The review continues where it stopped.',
  cancel: 'Stopping the review. Findings so far are kept.',
};
const DONE: Record<CaseControlAction, string> = {
  pause: 'Paused.',
  resume: 'Resume queued.',
  cancel: 'Review stopped.',
};

/**
 * Sends pause/resume/cancel for a project's cases and tracks which case has a request in flight.
 * `pending` clears when the caller sees the status change (`settle`) or when the request fails.
 */
export function useRunControl(api: ApiClient, projectId: string, onDone?: () => void) {
  const toast = useToast();
  const [pending, setPending] = useState<Record<string, CaseControlAction>>({});
  const clear = useCallback(
    (caseId: string) =>
      setPending((p) => {
        if (!(caseId in p)) return p;
        const { [caseId]: _, ...rest } = p;
        return rest;
      }),
    [],
  );
  const act = useCallback(
    async (caseId: string, action: CaseControlAction) => {
      setPending((p) => ({ ...p, [caseId]: action }));
      try {
        const result = await api.controlCase(projectId, caseId, action);
        // A running job was signalled: the case reports the outcome after its current step. Otherwise
        // the service recorded the stop itself, or queued the resume.
        const signalled = action !== 'resume' && Boolean(result.jobId);
        if (result.remote) toast(`${SENT[action]} The worker running it stops at its next check-in.`, 'info');
        else toast(signalled || action === 'resume' ? SENT[action] : DONE[action], 'info');
        if (!signalled && action !== 'resume') clear(caseId);
      } catch (err) {
        clear(caseId);
        toast(err instanceof ApiError && err.status === 409 ? `Not possible now: ${err.message}` : (err as Error).message, 'danger');
      } finally {
        onDone?.();
      }
    },
    [api, projectId, toast, onDone, clear],
  );
  /** Clears the request of a case once its status shows the outcome. */
  const settle = useCallback((caseId: string, status: string) => {
    setPending((p) => {
      const action = p[caseId];
      if (!action) return p;
      const done =
        (action === 'pause' && status !== 'RUNNING') ||
        (action === 'cancel' && status !== 'RUNNING' && status !== 'PARKED' && status !== 'PAUSED') ||
        (action === 'resume' && status !== 'PAUSED');
      if (!done) return p;
      const { [caseId]: _, ...rest } = p;
      return rest;
    });
  }, []);
  return { pending, act, settle };
}

/** Cancel button of a review that is still scanning (no case yet), with an inline confirmation. */
export function CancelJobButton({ api, projectId, jobId, onDone }: { api: ApiClient; projectId: string; jobId: string; onDone: () => void }) {
  const toast = useToast();
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const cancel = async () => {
    setBusy(true);
    try {
      await api.cancelJob(projectId, jobId);
      toast('Review cancelled before it started.', 'info');
    } catch (err) {
      toast((err as Error).message, 'danger');
    } finally {
      setBusy(false);
      setConfirming(false);
      onDone();
    }
  };
  if (confirming)
    return (
      <span className="inline-confirm">
        <button type="button" className="btn btn-sm btn-danger" disabled={busy} onClick={() => void cancel()}>
          {busy ? <Spinner size={12} /> : <Icon name="stop" size={12} />}
          Cancel review
        </button>
        <button type="button" className="btn btn-sm btn-ghost" disabled={busy} onClick={() => setConfirming(false)}>
          Keep
        </button>
      </span>
    );
  return (
    <button type="button" className="btn btn-sm btn-ghost" onClick={() => setConfirming(true)}>
      <Icon name="x" size={12} />
      Cancel
    </button>
  );
}
