import { createHmac } from 'node:crypto';
import type { Logger } from '@spinxsca/core';

export interface NotificationEvent {
  event: 'findings.new' | 'scan.failed';
  project: { projectId: string; name: string };
  branch: string;
  scanId?: string;
  jobId: string;
  trigger: 'webhook' | 'api' | 'reassessment';
  findings: Array<{
    findingId: string;
    title: string;
    severity: string;
    category: string;
    kev?: boolean;
    epss?: number;
    causes: string[];
  }>;
  url?: string;
  error?: string;
}

/**
 * Outgoing webhooks (JSON POST, `X-Spinxsca-Signature: sha256=<hmac>` over the raw body). Delivery is
 * best effort: failures are logged, never retried, and never fail the job.
 */
export class Notifier {
  constructor(
    private readonly options: {
      urls: readonly string[];
      secret?: string;
      logger: Logger;
      fetch?: typeof fetch;
      timeoutMs?: number;
    },
  ) {}

  async send(event: NotificationEvent): Promise<void> {
    if (this.options.urls.length === 0) return;
    const body = JSON.stringify(event);
    const headers: Record<string, string> = { 'content-type': 'application/json', 'user-agent': 'spinxsca-server' };
    if (this.options.secret)
      headers['x-spinxsca-signature'] =
        `sha256=${createHmac('sha256', this.options.secret).update(body).digest('hex')}`;
    const http = this.options.fetch ?? fetch;
    await Promise.all(
      this.options.urls.map(async (url) => {
        try {
          const res = await http(url, {
            method: 'POST',
            headers,
            body,
            signal: AbortSignal.timeout(this.options.timeoutMs ?? 10_000),
          });
          if (!res.ok) this.options.logger.warn(`notification to ${url} returned HTTP ${res.status}`);
        } catch (err) {
          this.options.logger.warn(`notification to ${url} failed: ${(err as Error).message}`);
        }
      }),
    );
  }
}
