import { type FormEvent, useEffect, useState } from 'react';
import type { ApiClient } from '../api/client';
import type { Project } from '../api/types';
import type { Health } from '../App';
import { Icon } from '../components/icons';
import { Card, PageHeader, Pill, Spinner, useToast } from '../components/ui';
import { deleteProviderKey, inDesktopShell, providerKeyPresent, setProviderKey } from '../lib/shell';

const LEVELS = [
  { value: 'off', label: 'Off', description: 'Scanners only; no model calls.' },
  { value: 'explain', label: 'Explain', description: 'A model explains each finding in plain language.' },
  { value: 'standard', label: 'Standard', description: 'A model investigates findings and proposes verdicts.' },
  { value: 'deep', label: 'Deep', description: 'Autonomous, governed review with objectives and approvals.' },
] as const;

/** Per-project AI settings (admin), local credentials and the environment reviews depend on. */
export function Settings({
  api,
  projects,
  health,
  baseUrl,
  onChanged,
}: {
  api: ApiClient;
  projects: Project[];
  health: Health;
  baseUrl: string;
  onChanged: () => void;
}) {
  const toast = useToast();
  const native = inDesktopShell();
  const [hasKey, setHasKey] = useState<boolean | undefined>();
  const [key, setKey] = useState('');
  const [replacing, setReplacing] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [working, setWorking] = useState(false);
  const [saving, setSaving] = useState<string | undefined>();

  useEffect(() => {
    void providerKeyPresent('anthropic').then((v) => setHasKey(v ?? false));
  }, []);

  const update = async (p: Project, level: string) => {
    setSaving(p.projectId);
    try {
      await api.setAi(p.projectId, { level, ...(p.ai?.goal ? { goal: p.ai.goal } : {}) });
      toast(`${p.name}: AI level set to ${level}`);
      onChanged();
    } catch (err) {
      toast((err as Error).message, 'danger');
    } finally {
      setSaving(undefined);
    }
  };

  const saveKey = async (e: FormEvent) => {
    e.preventDefault();
    setWorking(true);
    try {
      await setProviderKey('anthropic', key.trim());
      setKey('');
      setHasKey(true);
      setReplacing(false);
      toast('Key saved to the keychain. The local service restarts to use it.');
    } catch (err) {
      toast(String((err as Error)?.message ?? err), 'danger');
    } finally {
      setWorking(false);
    }
  };

  const removeKey = async () => {
    setWorking(true);
    try {
      await deleteProviderKey('anthropic');
      setHasKey(false);
      setConfirmRemove(false);
      toast('Key removed from the keychain.');
    } catch (err) {
      toast(String((err as Error)?.message ?? err), 'danger');
    } finally {
      setWorking(false);
    }
  };

  const docker = health.docker;
  return (
    <div className="page">
      <PageHeader title="Settings" subtitle="Credentials, AI per project and the environment reviews run in." />
      <div className="settings">
        <Card title="Model provider" icon="key">
          <div className="setting-row">
            <div className="setting-text">
              <div className="setting-title">Anthropic API key</div>
              <div className="setting-hint">Kept in the OS keychain and handed only to the local service. Saving or removing it restarts the service.</div>
            </div>
            <div className="setting-control">
              {!native ? (
                <Pill>Desktop app only</Pill>
              ) : hasKey === undefined ? (
                <Spinner size={14} />
              ) : hasKey ? (
                <Pill tone="ok" dot>
                  Stored in keychain
                </Pill>
              ) : (
                <Pill tone="warn" dot>
                  Not set
                </Pill>
              )}
            </div>
          </div>
          {native && hasKey !== undefined && (
            <div className="setting-actions">
              {!hasKey || replacing ? (
                <form className="key-form" onSubmit={(e) => void saveKey(e)}>
                  <input
                    type="password"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="sk-ant-…"
                    aria-label="Anthropic API key"
                    value={key}
                    onChange={(e) => setKey(e.target.value)}
                  />
                  <button type="submit" className="btn btn-primary" disabled={working || key.trim().length < 20}>
                    <Icon name="lock" size={14} />
                    {hasKey ? 'Replace key' : 'Save to keychain'}
                  </button>
                  {replacing && (
                    <button type="button" className="btn btn-ghost" onClick={() => setReplacing(false)}>
                      Cancel
                    </button>
                  )}
                </form>
              ) : confirmRemove ? (
                <div className="confirm">
                  <span>Remove the key? AI reviews stop working until a new key is saved.</span>
                  <button type="button" className="btn btn-danger" disabled={working} onClick={() => void removeKey()}>
                    <Icon name="trash" size={14} />
                    Remove key
                  </button>
                  <button type="button" className="btn btn-ghost" onClick={() => setConfirmRemove(false)}>
                    Cancel
                  </button>
                </div>
              ) : (
                <>
                  <button type="button" className="btn" onClick={() => setReplacing(true)}>
                    Replace key
                  </button>
                  <button type="button" className="btn btn-danger-outline" onClick={() => setConfirmRemove(true)}>
                    Remove the Anthropic key from the keychain
                  </button>
                </>
              )}
            </div>
          )}
        </Card>

        <Card title="AI per project" icon="sparkles">
          {projects.length === 0 ? (
            <p className="muted">Add a project to choose its AI level.</p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Project</th>
                  <th>AI level</th>
                  <th className="hide-narrow">What it does</th>
                </tr>
              </thead>
              <tbody>
                {projects.map((p) => {
                  const level = p.ai?.level ?? 'off';
                  return (
                    <tr key={p.projectId}>
                      <td>
                        <strong>{p.name}</strong>
                      </td>
                      <td>
                        <span className="select-wrap">
                          <select aria-label={`AI level for ${p.name}`} value={level} disabled={saving === p.projectId} onChange={(e) => void update(p, e.target.value)}>
                            {LEVELS.map((l) => (
                              <option key={l.value} value={l.value}>
                                {l.label}
                              </option>
                            ))}
                          </select>
                          {saving === p.projectId && <Spinner size={13} />}
                        </span>
                      </td>
                      <td className="muted hide-narrow">{LEVELS.find((l) => l.value === level)?.description ?? level}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          <p className="card-note">
            The level applies to scans of the project (CLI, webhooks). Reviews started from this app always run the deep,
            governed review.
          </p>
        </Card>

        <Card
          title="Environment"
          icon="server"
          actions={
            <button type="button" className="btn btn-sm" onClick={health.recheckDocker}>
              <Icon name="refresh" size={13} />
              Check again
            </button>
          }
        >
          <dl className="env">
            <div>
              <dt>Local service</dt>
              <dd>
                <Pill tone={health.service === 'online' ? 'ok' : health.service === 'offline' ? 'danger' : 'neutral'} dot>
                  {health.service === 'online' ? 'Running' : health.service === 'offline' ? 'Not answering' : 'Connecting'}
                </Pill>
                <code className="tag-code">{baseUrl}</code>
              </dd>
            </div>
            <div>
              <dt>Docker</dt>
              <dd>
                {!native ? (
                  <Pill>Checked only in the desktop app</Pill>
                ) : !docker ? (
                  <Spinner size={13} />
                ) : docker.available ? (
                  <>
                    <Pill tone="ok" dot>
                      Ready
                    </Pill>
                    {docker.version && <span className="muted">Docker {docker.version}</span>}
                  </>
                ) : (
                  <>
                    <Pill tone="danger" dot>
                      Unavailable
                    </Pill>
                    <span className="muted">{docker.detail}</span>
                  </>
                )}
              </dd>
            </div>
          </dl>
        </Card>

        <div className="note">
          <Icon name="lock" size={16} />
          <p>
            Autonomy mode, reviewer model, budgets and whether proofs of concept run without asking are operator settings in{' '}
            <code>spinxsca.yaml</code>. The repository under review can never change them.
          </p>
        </div>
      </div>
    </div>
  );
}
