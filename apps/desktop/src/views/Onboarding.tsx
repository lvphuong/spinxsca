import { useEffect, useState } from 'react';
import type { ApiClient } from '../api/client';
import { type DockerStatus, dockerStatus, providerKeyPresent, setProviderKey } from '../lib/shell';

/** First run: Docker for the sandbox, a model provider key in the OS keychain, a reachable sidecar. */
export function Onboarding({ api, onDone }: { api: ApiClient; onDone: () => void }) {
  const [docker, setDocker] = useState<DockerStatus | undefined>();
  const [sidecar, setSidecar] = useState<string>('checking…');
  const [hasKey, setHasKey] = useState<boolean | undefined>();
  const [key, setKey] = useState('');
  useEffect(() => {
    void dockerStatus().then((d) => setDocker(d ?? { available: false, detail: 'not running inside the desktop shell' }));
    void api.health().then(
      () => setSidecar('running'),
      (e) => setSidecar(`unreachable: ${(e as Error).message}`),
    );
    void providerKeyPresent('anthropic').then((v) => setHasKey(v ?? false));
  }, [api]);
  const save = async () => {
    await setProviderKey('anthropic', key.trim());
    setKey('');
    setHasKey(true);
  };
  return (
    <section>
      <h1>Set up Spinx SecureCode AI</h1>
      <ol className="steps">
        <li>
          <strong>Docker</strong> — scanners and the analysis sandbox run in containers without network.{' '}
          {docker ? (docker.available ? <span className="ok">ready ({docker.version})</span> : <span className="error">{docker.detail}</span>) : 'checking…'}
        </li>
        <li>
          <strong>Local service</strong> — {sidecar}
        </li>
        <li>
          <strong>Model provider</strong> — the key is stored in the OS keychain and given only to the local service.{' '}
          {hasKey ? (
            <span className="ok">key stored</span>
          ) : (
            <span>
              <input type="password" autoComplete="off" placeholder="Anthropic API key" value={key} onChange={(e) => setKey(e.target.value)} />{' '}
              <button type="button" disabled={key.trim().length < 20} onClick={() => void save()}>
                Save to keychain
              </button>
            </span>
          )}
        </li>
      </ol>
      <button type="button" className="primary" disabled={sidecar !== 'running'} onClick={onDone}>
        Continue
      </button>
    </section>
  );
}
