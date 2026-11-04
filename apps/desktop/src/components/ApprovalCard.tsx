import { useState } from 'react';
import type { ApprovalRecord } from '../api/types';
import { DiffView } from './DiffView';

const EFFECT: Record<ApprovalRecord['effect'], { label: string; tone: 'safe' | 'warn' | 'danger' }> = {
  sandbox: { label: 'Stays in the sandbox (no network, copy of your code)', tone: 'safe' },
  workspace: { label: 'Writes to a workspace copy, not your repository', tone: 'safe' },
  repository: { label: 'Changes your repository', tone: 'danger' },
  external: { label: 'Acts on an external system', tone: 'danger' },
  governance: { label: 'Changes how findings are judged', tone: 'warn' },
};

const GRANT_LABEL = { once: 'Approve once', case: 'Approve for this review', standing: 'Always allow this target' } as const;

export interface Decision {
  decision: 'approve' | 'deny';
  grant?: 'once' | 'case' | 'standing';
  reason?: string;
}

/**
 * One action waiting for a human. The card states where the effect lands, shows the real diff for
 * patches and harnesses, offers only the grants the policy allows, and marks human-only requests.
 */
export function ApprovalCard({ approval, onDecide, busy }: { approval: ApprovalRecord; onDecide: (d: Decision) => void; busy?: boolean }) {
  const [showArgs, setShowArgs] = useState(false);
  const [reason, setReason] = useState('');
  const effect = EFFECT[approval.effect] ?? EFFECT.governance;
  const grants = approval.humanOnly ? (['once'] as const) : approval.offeredGrants;
  return (
    <article className={`approval tone-${effect.tone}`} aria-label={approval.title}>
      <header>
        <h3>{approval.title}</h3>
        <div className="chips">
          <span className="chip">{approval.tool}</span>
          <span className="chip">{approval.risk}</span>
          {approval.humanOnly && <span className="chip danger" title="Only a human can approve this; it is never remembered">human decision</span>}
        </div>
      </header>
      <p className={`effect ${effect.tone}`}>{effect.label}</p>
      {approval.summary && <p className="summary">{approval.summary}</p>}
      {approval.targets.length > 0 && (
        <p className="targets">
          Targets: {approval.targets.map((t) => <code key={`${t.kind}:${t.value}`}>{t.value}</code>)}
        </p>
      )}
      {approval.diff && <DiffView diff={approval.diff} />}
      <button type="button" className="link" onClick={() => setShowArgs((v) => !v)}>
        {showArgs ? 'Hide arguments' : 'Show arguments'}
      </button>
      {showArgs && <pre className="args">{approval.argsPreview}</pre>}
      <footer>
        <input placeholder="Reason (optional)" value={reason} onChange={(e) => setReason(e.target.value)} />
        {grants.map((g) => (
          <button key={g} type="button" className={g === 'once' ? 'primary' : ''} disabled={busy} onClick={() => onDecide({ decision: 'approve', grant: g, ...(reason ? { reason } : {}) })}>
            {GRANT_LABEL[g]}
          </button>
        ))}
        <button type="button" className="danger" disabled={busy} onClick={() => onDecide({ decision: 'deny', ...(reason ? { reason } : {}) })}>
          Deny
        </button>
      </footer>
    </article>
  );
}
