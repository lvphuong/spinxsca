import { SseParser } from '../lib/sse';
import type {
  ApprovalRecord,
  CaseControlAction,
  CaseControlResult,
  CaseView,
  JobEntry,
  Project,
  ReviewCase,
  ReviewDefaults,
  ReviewRunOptions,
} from './types';

/** Connection to the local sidecar, injected by the desktop shell before the page loads. */
export interface Connection {
  baseUrl: string;
  token: string;
}

declare global {
  interface Window {
    __SPINXSCA__?: Connection;
  }
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/** Typed client of the sidecar API. The token stays in memory; it is never stored by the page. */
export class ApiClient {
  constructor(
    private readonly conn: Connection,
    private readonly fetchImpl: typeof fetch = (...a) => fetch(...a),
  ) {}

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.fetchImpl(`${this.conn.baseUrl}${path}`, {
      method,
      headers: { authorization: `Bearer ${this.conn.token}`, ...(body ? { 'content-type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const json = (await res.json().catch(() => ({}))) as T & { error?: string };
    if (!res.ok) throw new ApiError(res.status, json.error ?? `HTTP ${res.status}`);
    return json;
  }

  health = () => this.call<{ status: string }>('GET', '/v1/health');
  /** The server answers with a bare array (older builds wrapped it in `{ projects }`). */
  projects = async () => {
    const body = await this.call<Project[] | { projects?: Project[] }>('GET', '/v1/projects');
    return Array.isArray(body) ? body : (body.projects ?? []);
  };
  createProject = (input: { name: string; path: string }) =>
    this.call<Project>('POST', '/v1/projects', {
      name: input.name,
      source: { kind: 'local', path: input.path },
    });
  setAi = (projectId: string, ai: { level: string; goal?: string; objectives?: string[] }) =>
    this.call('PUT', `/v1/projects/${encodeURIComponent(projectId)}/ai`, ai);
  startReview = (
    projectId: string,
    input: { branch: string; goal?: string; objectives?: string[]; options?: ReviewRunOptions },
  ) => this.call<{ job: { jobId: string } }>('POST', `/v1/projects/${encodeURIComponent(projectId)}/reviews`, input);
  /** Defaults and ceilings of review options; older services answer 404, which callers treat as unknown. */
  reviewOptions = () => this.call<ReviewDefaults>('GET', '/v1/review-options');
  /** Cancels a queued or running job (a review that is still scanning). */
  cancelJob = (projectId: string, jobId: string) =>
    this.call<{ job: JobEntry; stoppedNow: boolean }>(
      'POST',
      `/v1/projects/${encodeURIComponent(projectId)}/jobs/${encodeURIComponent(jobId)}/cancel`,
    );
  /** Pauses, resumes or cancels a review case. */
  controlCase = (projectId: string, caseId: string, action: CaseControlAction, reason?: string) =>
    this.call<CaseControlResult>(
      'POST',
      `/v1/projects/${encodeURIComponent(projectId)}/cases/${encodeURIComponent(caseId)}/control`,
      { action, ...(reason ? { reason } : {}) },
    );
  projectJobs = (projectId: string) =>
    this.call<JobEntry[]>('GET', `/v1/projects/${encodeURIComponent(projectId)}/jobs`);
  cases = async (projectId: string) =>
    (await this.call<{ cases: ReviewCase[] }>('GET', `/v1/projects/${encodeURIComponent(projectId)}/cases`)).cases;
  caseView = (projectId: string, caseId: string) =>
    this.call<CaseView>('GET', `/v1/projects/${encodeURIComponent(projectId)}/cases/${encodeURIComponent(caseId)}`);
  inbox = async () => (await this.call<{ approvals: ApprovalRecord[] }>('GET', '/v1/inbox')).approvals;
  decide = (
    projectId: string,
    approvalId: string,
    decision: { decision: 'approve' | 'deny'; grant?: string; reason?: string },
  ) =>
    this.call<{ approval: ApprovalRecord }>(
      'POST',
      `/v1/projects/${encodeURIComponent(projectId)}/approvals/${encodeURIComponent(approvalId)}`,
      decision,
    );

  /** Streams case events (audit and journal) from `sinceSeq`; resolves when the stream ends. */
  async events(
    projectId: string,
    caseId: string,
    onEvent: (event: { event: string; data: unknown }) => void,
    options: { sinceSeq?: number; signal?: AbortSignal } = {},
  ): Promise<void> {
    const res = await this.fetchImpl(
      `${this.conn.baseUrl}/v1/projects/${encodeURIComponent(projectId)}/cases/${encodeURIComponent(caseId)}/events?sinceSeq=${options.sinceSeq ?? -1}`,
      {
        headers: { authorization: `Bearer ${this.conn.token}`, accept: 'text/event-stream' },
        ...(options.signal ? { signal: options.signal } : {}),
      },
    );
    if (!res.ok || !res.body) throw new ApiError(res.status, 'event stream unavailable');
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    const parser = new SseParser();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      for (const e of parser.push(decoder.decode(value, { stream: true }))) {
        try {
          onEvent({ event: e.event, data: JSON.parse(e.data) });
        } catch {
          onEvent({ event: e.event, data: e.data });
        }
      }
    }
  }
}
