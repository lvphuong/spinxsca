import { useState } from 'react';
import type { ApiClient } from '../api/client';
import type { Project } from '../api/types';
import { deleteProviderKey } from '../lib/shell';

/** Per-project AI settings (admin) and local credentials. Autonomy limits live in the operator config file. */
export function Settings({ api, projects, onChanged }: { api: ApiClient; projects: Project[]; onChanged: () => void }) {
  const [message, setMessage] = useState<string | undefined>();
  const update = async (p: Project, level: string) => {
    await api.setAi(p.projectId, { level, ...(p.ai?.goal ? { goal: p.ai.goal } : {}) });
    setMessage(`${p.name}: AI ${level}`);
    onChanged();
  };
  return (
    <section>
      <h1>Settings</h1>
      {message && <p className="ok">{message}</p>}
      <h2>AI per project</h2>
      <table>
        <tbody>
          {projects.map((p) => (
            <tr key={p.projectId}>
              <td>{p.name}</td>
              <td>
                <select value={p.ai?.level ?? 'off'} onChange={(e) => void update(p, e.target.value)}>
                  {['off', 'explain', 'standard', 'deep'].map((l) => (
                    <option key={l} value={l}>
                      {l}
                    </option>
                  ))}
                </select>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted">
        Autonomy mode, reviewer model, budgets and whether proofs of concept run without asking are operator settings in
        spinxsca.yaml; the repository under review can never change them.
      </p>
      <h2>Credentials</h2>
      <button type="button" className="danger" onClick={() => void deleteProviderKey('anthropic').then(() => setMessage('key removed'))}>
        Remove the Anthropic key from the keychain
      </button>
    </section>
  );
}
