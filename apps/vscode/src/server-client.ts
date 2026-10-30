import type { ServerFinding } from './model';

export interface GateResult {
  passed: boolean;
  checks: Array<{ id: string; passed: boolean; message: string }>;
}

/** Read-only client for a spinxsca server (findings and gate of one branch). */
export class ServerClient {
  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
    private readonly http: typeof fetch = fetch,
  ) {}

  findings(projectId: string, branch: string): Promise<ServerFinding[]> {
    return this.get(`/v1/projects/${encodeURIComponent(projectId)}/findings?branch=${encodeURIComponent(branch)}`);
  }

  gate(projectId: string, branch: string): Promise<GateResult> {
    return this.get(`/v1/projects/${encodeURIComponent(projectId)}/gate?branch=${encodeURIComponent(branch)}`);
  }

  findingUrl(projectId: string, findingId: string): string {
    return `${this.baseUrl.replace(/\/+$/, '')}/ui/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}`;
  }

  private async get<T>(path: string): Promise<T> {
    const res = await this.http(`${this.baseUrl.replace(/\/+$/, '')}${path}`, {
      headers: { authorization: `Bearer ${this.token}` },
    });
    if (res.status === 401) throw new Error('the server rejected the API token (run "spinxsca: Set server API token")');
    if (!res.ok) throw new Error(`server returned HTTP ${res.status}`);
    return (await res.json()) as T;
  }
}
