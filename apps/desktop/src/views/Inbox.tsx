import { useState } from 'react';
import type { ApiClient } from '../api/client';
import type { ApprovalRecord } from '../api/types';
import { ApprovalCard, type Decision } from '../components/ApprovalCard';
import { Banner, EmptyState, PageHeader, Pill, useToast } from '../components/ui';

/** Every action review cases wait for, across projects. The first answer wins on the server. */
export function Inbox({
  api,
  approvals,
  onChanged,
  onOpenCase,
}: {
  api: ApiClient;
  approvals: ApprovalRecord[];
  onChanged: () => void;
  onOpenCase: (projectId: string, caseId: string) => void;
}) {
  const toast = useToast();
  const [busy, setBusy] = useState<string | undefined>();
  const [error, setError] = useState<string | undefined>();
  const decide = async (a: ApprovalRecord, d: Decision) => {
    setBusy(a.approvalId);
    setError(undefined);
    try {
      await api.decide(a.project?.projectId ?? a.projectId, a.approvalId, d);
      toast(d.decision === 'deny' ? 'Denied. The review continues without it.' : 'Approved. The review resumes shortly.');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(undefined);
      onChanged();
    }
  };
  const highImpact = approvals.filter((a) => a.effect === 'repository' || a.effect === 'external').length;
  return (
    <div className="page">
      <PageHeader
        title="Inbox"
        subtitle="Actions your reviews are waiting on. Nothing runs until someone decides; the first answer wins."
        actions={
          approvals.length > 0 && (
            <div className="summary-pills">
              <Pill tone="warn" dot>
                {approvals.length} waiting
              </Pill>
              {highImpact > 0 && (
                <Pill tone="danger" dot>
                  {highImpact} change{highImpact === 1 ? 's' : ''} code or systems
                </Pill>
              )}
            </div>
          )
        }
      />
      {error && (
        <Banner tone="danger" title="The decision was not recorded" onDismiss={() => setError(undefined)}>
          {error}
        </Banner>
      )}
      {approvals.length === 0 ? (
        <EmptyState icon="checkCircle" title="You're all caught up">
          When a review needs permission — to run a proof of concept, or to apply a verified fix — the request appears here
          and you get a notification.
        </EmptyState>
      ) : (
        <div className="stack">
          {approvals.map((a) => (
            <ApprovalCard
              key={a.approvalId}
              approval={a}
              busy={busy === a.approvalId}
              onDecide={(d) => void decide(a, d)}
              context={{
                ...(a.project ? { project: a.project.name } : {}),
                onOpen: () => onOpenCase(a.project?.projectId ?? a.projectId, a.caseId),
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}
