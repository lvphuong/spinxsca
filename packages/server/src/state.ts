import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { ArtifactStore, ScanRepository } from '@spinxsca/core';
import { FsArtifactStore, PgScanRepository, SqliteScanRepository } from '@spinxsca/storage';
import pg from 'pg';
import type { ProjectWorkspace } from './workspace';

export interface ProjectState {
  repo: ScanRepository;
  artifacts: ArtifactStore;
  /** Engine project id inside the state database (undefined before the first scan). */
  engineProjectId(): Promise<string | undefined>;
}

/**
 * Handles on each project's state, opened lazily and kept for the server's life: a SQLite file per
 * project by default, or one PostgreSQL schema per project when a database URL is configured
 * (ADR-037). Artifacts stay on the server's disk in both cases.
 */
export class ProjectStates {
  private readonly open = new Map<string, { close: () => Promise<void> | void; state: ProjectState }>();
  private readonly pool: pg.Pool | undefined;

  constructor(
    private readonly workspace: ProjectWorkspace,
    options: { databaseUrl?: string } = {},
  ) {
    this.pool = options.databaseUrl ? new pg.Pool({ connectionString: options.databaseUrl, max: 10 }) : undefined;
  }

  get backend(): 'sqlite' | 'postgres' {
    return this.pool ? 'postgres' : 'sqlite';
  }

  get(projectId: string): ProjectState {
    const cached = this.open.get(projectId);
    if (cached) return cached.state;
    const dir = this.workspace.paths(projectId).state;
    mkdirSync(join(dir, 'artifacts'), { recursive: true });
    const repo = this.pool
      ? PgScanRepository.open({ pool: this.pool, schema: PgScanRepository.schemaFor(projectId) })
      : SqliteScanRepository.open(join(dir, 'state.db'));
    const state: ProjectState = {
      repo,
      artifacts: new FsArtifactStore(join(dir, 'artifacts')),
      engineProjectId: async () => (await repo.getProject())?.project.projectId,
    };
    this.open.set(projectId, { close: () => repo.close(), state });
    return state;
  }

  /** Whether the project may have state (always true with PostgreSQL; the schema is created on demand). */
  exists(projectId: string): boolean {
    return this.pool !== undefined || existsSync(join(this.workspace.paths(projectId).state, 'state.db'));
  }

  async close(): Promise<void> {
    for (const { close } of this.open.values()) await close();
    this.open.clear();
    await this.pool?.end();
  }
}
