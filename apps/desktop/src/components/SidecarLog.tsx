import type { SidecarStatus } from '../lib/shell';

/** End of the local service log at its last failed start, collapsed by default. */
export function SidecarLogTail({ status }: { status: SidecarStatus | undefined }) {
  if (!status?.lastError || !status.logTail) return null;
  return (
    <details className="sidecar-log">
      <summary>Last lines of {status.logPath}</summary>
      <pre className="code-block">{status.logTail}</pre>
    </details>
  );
}
