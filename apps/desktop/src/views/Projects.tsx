import { useState } from 'react';
import type { ApiClient } from '../api/client';
import type { Project } from '../api/types';
import { pickFolder } from '../lib/shell';

export function Projects({ api, projects, onChanged, onOpen }: { api: ApiClient; projects: Project[]; onChanged: () => void; onOpen: (p: Project) => void }) {
  const [error, setError] = useState<string | undefined>();
  const add = async () => {
    setError(undefined);
    const path = await pickFolder();
    if (!path) return;
    const name = (path.split(/[\\/]/).filter(Boolean).pop() ?? 'project').replace(/[^A-Za-z0-9._-]/g, '-').slice(0, 100);
    try {
      await api.createProject({ name, path });
      onChanged();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  return (
    <section>
      <h1>Projects</h1>
      {error && <p className="error" role="alert">{error}</p>}
      <button type="button" className="primary" onClick={() => void add()}>
        Add a folder
      </button>
      <ul className="list">
        {projects.map((p) => (
          <li key={p.projectId}>
            <button type="button" className="link" onClick={() => onOpen(p)}>
              {p.name}
            </button>
            <span className="muted"> {p.source.kind === 'local' ? p.source.path : p.source.url}</span>
            {p.ai && <span className="chip">AI {p.ai.level}</span>}
          </li>
        ))}
      </ul>
    </section>
  );
}
