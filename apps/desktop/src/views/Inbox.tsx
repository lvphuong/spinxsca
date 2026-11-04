import { useState } from 'react';
import type { ApiClient } from '../api/client';
import type { ApprovalRecord } from '../api/types';
import { ApprovalCard, type Decision } from '../components/ApprovalCard';

/** Every action review cases wait for, across projects. The first answer wins on the server. */
export function Inbox({ api, approvals, onChanged }: { api: ApiClient; approvals: ApprovalRecord[]; onChanged: () => void }) {
  const [busy, setBusy] = useState<string | undefined>();
  const [error, setError] = useState<string | undefined>();
  const decide = async (a: ApprovalRecord, d: Decision) => {
    setBusy(a.approvalId);
    setError(undefined);
    try {
      await api.decide(a.project?.projectId ?? a.projectId, a.approvalId, d);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(undefined);
      onChanged();
    }
  };
  return (
    <section>
      <h1>Inbox</h1>
      {error && <p className="error" role="alert">{error}</p>}
      {approvals.length === 0 ? (
        <p className="muted">Nothing is waiting for you.</p>
      ) : (
        approvals.map((a) => (
          <div key={a.approvalId}>
            {a.project && <p className="muted">{a.project.name} · case {a.caseId}</p>}
            <ApprovalCard approval={a} busy={busy === a.approvalId} onDecide={(d) => void decide(a, d)} />
          </div>
        ))
      )}
    </section>
  );
}
