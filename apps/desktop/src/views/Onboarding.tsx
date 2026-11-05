import { type FormEvent, type ReactNode, useCallback, useEffect, useState } from 'react';
import type { ApiClient } from '../api/client';
import { Icon } from '../components/icons';
import { Spinner } from '../components/ui';
import { type DockerStatus, dockerStatus, inDesktopShell, openExternal, providerKeyPresent, setProviderKey } from '../lib/shell';

type StepState = 'checking' | 'ready' | 'problem' | 'skipped';

/**
 * First run and every launch: Docker for the sandbox, a model provider key in the OS keychain, a
 * reachable sidecar. When everything is ready the app opens directly; otherwise this page says what
 * is missing and how to fix it. The sidecar may still be starting (or restarting after a key
 * change), so its health is polled until it answers.
 */
export function Onboarding({ api, onDone }: { api: ApiClient; onDone: () => void }) {
  const native = inDesktopShell();
  const [docker, setDocker] = useState<DockerStatus | undefined>();
  const [checkingDocker, setCheckingDocker] = useState(false);
  const [service, setService] = useState<{ state: 'checking' | 'online' | 'offline'; detail?: string }>({ state: 'checking' });
  const [serviceAttempt, setServiceAttempt] = useState(0);
  const [hasKey, setHasKey] = useState<boolean | undefined>();
  const [key, setKey] = useState('');
  const [saving, setSaving] = useState(false);
  const [keyError, setKeyError] = useState<string | undefined>();

  const checkDocker = useCallback(() => {
    setCheckingDocker(true);
    void dockerStatus()
      .then((d) => setDocker(d ?? { available: false, detail: 'Checked only inside the desktop app.' }))
      .finally(() => setCheckingDocker(false));
  }, []);

  useEffect(() => {
    checkDocker();
    void providerKeyPresent('anthropic').then((v) => setHasKey(v ?? false));
  }, [checkDocker]);

  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      try {
        await api.health();
        if (!stopped) setService({ state: 'online' });
      } catch (err) {
        if (stopped) return;
        setService({ state: 'offline', detail: (err as Error).message });
        timer = setTimeout(() => void tick(), 2000);
      }
    };
    void tick();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
  }, [api, serviceAttempt]);

  const ready = service.state === 'online' && docker?.available === true && hasKey === true;
  useEffect(() => {
    if (ready) onDone();
  }, [ready, onDone]);

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setKeyError(undefined);
    try {
      await setProviderKey('anthropic', key.trim());
      setKey('');
      setHasKey(true);
      // Storing the key restarts the local service so it picks the key up.
      setService({ state: 'checking' });
      setServiceAttempt((n) => n + 1);
    } catch (err) {
      setKeyError(String((err as Error)?.message ?? err));
    } finally {
      setSaving(false);
    }
  };

  // First pass still running: a quiet splash instead of a checklist that flashes and disappears.
  if (docker === undefined || hasKey === undefined || (service.state === 'checking' && serviceAttempt === 0) || ready) {
    return (
      <div className="setup">
        <div className="splash">
          <span className="brand-mark brand-mark-lg">
            <Icon name="shieldCheck" size={26} />
          </span>
          <Spinner size={18} label="Starting Spinx" />
        </div>
      </div>
    );
  }

  const dockerState: StepState = !native ? 'skipped' : checkingDocker ? 'checking' : docker.available ? 'ready' : 'problem';
  const serviceState: StepState = service.state === 'online' ? 'ready' : 'checking';
  const keyState: StepState = !native ? 'skipped' : hasKey ? 'ready' : 'problem';
  const doneCount = [dockerState, serviceState, keyState].filter((s) => s === 'ready').length;

  return (
    <div className="setup">
      <div className="setup-card">
        <header className="setup-header">
          <span className="brand-mark brand-mark-lg">
            <Icon name="shieldCheck" size={26} />
          </span>
          <div>
            <h1>Set up Spinx SecureCode AI</h1>
            <p>Three things make reviews work on this computer. {doneCount} of 3 ready.</p>
          </div>
        </header>
        <div className="setup-progress" aria-hidden="true">
          <span style={{ width: `${(doneCount / 3) * 100}%` }} />
        </div>

        <ol className="steps">
          <Step
            state={serviceState}
            icon="server"
            title="Local service"
            description="Runs scans and reviews on this computer, reachable only from this app."
            status={
              service.state === 'online'
                ? 'Running'
                : service.state === 'checking'
                  ? 'Restarting with the new settings…'
                  : 'Starting… this can take up to a minute on the first launch.'
            }
          />
          <Step
            state={dockerState}
            icon="box"
            title="Docker"
            description="Scanners and the analysis sandbox run in containers without network access."
            status={
              dockerState === 'skipped'
                ? 'Checked only in the desktop app.'
                : dockerState === 'checking'
                  ? 'Checking…'
                  : docker.available
                  ? `Ready${docker.version ? ` · Docker ${docker.version}` : ''}`
                  : `Not available — ${docker.detail}. Start Docker Desktop, then check again.`
            }
            action={
              dockerState === 'problem' && (
                <>
                  <button type="button" className="btn btn-sm" onClick={checkDocker}>
                    <Icon name="refresh" size={14} />
                    Check again
                  </button>
                  <button type="button" className="btn btn-sm btn-ghost" onClick={() => void openExternal('https://docs.docker.com/get-started/get-docker/')}>
                    Get Docker
                    <Icon name="external" size={13} />
                  </button>
                </>
              )
            }
          />
          <Step
            state={keyState}
            icon="key"
            title="Model provider key"
            description="Stored in the OS keychain and handed only to the local service. Needed for AI reviews; you can add it later in Settings."
            status={keyState === 'skipped' ? 'Stored only by the desktop app.' : hasKey ? 'Anthropic key stored in the keychain' : undefined}
          >
            {keyState === 'problem' && (
              <form className="key-form" onSubmit={(e) => void save(e)}>
                <input
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="Anthropic API key (sk-ant-…)"
                  aria-label="Anthropic API key"
                  value={key}
                  onChange={(e) => setKey(e.target.value)}
                />
                <button type="submit" className="btn" disabled={saving || key.trim().length < 20}>
                  {saving ? <Spinner size={13} /> : <Icon name="lock" size={14} />}
                  Save to keychain
                </button>
                {keyError && (
                  <p className="field-error" role="alert">
                    {keyError}
                  </p>
                )}
              </form>
            )}
          </Step>
        </ol>

        <footer className="setup-footer">
          <span className="muted">
            {service.state !== 'online'
              ? 'Continue becomes available when the local service answers.'
              : dockerState === 'problem'
                ? 'You can continue, but reviews need Docker.'
                : keyState === 'problem'
                  ? 'You can continue; AI reviews need a key.'
                  : 'Everything this browser session can check is ready.'}
          </span>
          <button type="button" className="btn btn-primary" disabled={service.state !== 'online'} onClick={onDone}>
            Continue
            <Icon name="chevronRight" size={15} />
          </button>
        </footer>
      </div>
    </div>
  );
}

const STEP_ICON = { checking: null, ready: 'checkCircle', problem: 'alertCircle', skipped: 'minusCircle' } as const;

function Step({
  state,
  icon,
  title,
  description,
  status,
  action,
  children,
}: {
  state: StepState;
  icon: 'server' | 'box' | 'key';
  title: string;
  description: string;
  status?: string | undefined;
  action?: ReactNode;
  children?: ReactNode;
}) {
  const mark = STEP_ICON[state];
  return (
    <li className={`step step-${state}`}>
      <span className="step-icon">
        <Icon name={icon} size={18} />
      </span>
      <div className="step-body">
        <div className="step-title">
          <strong>{title}</strong>
          <span className="step-state">{mark ? <Icon name={mark} size={16} /> : <Spinner size={14} />}</span>
        </div>
        <p className="step-description">{description}</p>
        {status && <p className="step-status">{status}</p>}
        {children}
        {action && <div className="step-actions">{action}</div>}
      </div>
    </li>
  );
}
