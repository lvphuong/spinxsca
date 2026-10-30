import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';
import type { SnapshotFile, SourceSnapshot } from '@spinxsca/schemas';
import Database from 'better-sqlite3';
import { extractFile } from './extract';
import { buildEdges, CodeGraph } from './graph';
import { languageOfPath } from './parser';
import { type CodeIndexData, EXTRACTOR_VERSION, type FileExtraction, INDEX_SCHEMA_VERSION } from './types';

export interface IndexStats {
  files: number;
  parsed: number;
  cached: number;
  symbols: number;
  endpoints: number;
  edges: number;
  errors: number;
}

export interface BuildInput {
  snapshot: SourceSnapshot;
  files: readonly SnapshotFile[];
  readText: (path: string) => Promise<string | undefined>;
  signal?: AbortSignal;
}

/**
 * Builds the index for a snapshot. Per-file extractions are cached by (content digest, extractor
 * version), so re-indexing after a small change parses only the changed files (ADR-008).
 */
export class IndexBuilder {
  private readonly db: Database.Database;

  constructor(cachePath: string) {
    mkdirSync(dirname(cachePath), { recursive: true });
    this.db = new Database(cachePath);
    this.db.pragma('journal_mode = WAL');
    this.db.exec(
      'CREATE TABLE IF NOT EXISTS file_cache (digest TEXT NOT NULL, extractor TEXT NOT NULL, path TEXT NOT NULL, data BLOB NOT NULL, PRIMARY KEY (digest, extractor, path))',
    );
  }

  close(): void {
    this.db.close();
  }

  async build(input: BuildInput): Promise<{ data: CodeIndexData; graph: CodeGraph; stats: IndexStats }> {
    const get = this.db.prepare<[string, string, string], { data: Buffer }>(
      'SELECT data FROM file_cache WHERE digest = ? AND extractor = ? AND path = ?',
    );
    const put = this.db.prepare(
      'INSERT OR REPLACE INTO file_cache (digest, extractor, path, data) VALUES (?, ?, ?, ?)',
    );
    const files: FileExtraction[] = [];
    const stats: IndexStats = { files: 0, parsed: 0, cached: 0, symbols: 0, endpoints: 0, edges: 0, errors: 0 };
    for (const file of input.files) {
      if (!languageOfPath(file.path)) continue;
      if (input.signal?.aborted) throw new Error('cancelled');
      stats.files++;
      const cached = get.get(file.digest, EXTRACTOR_VERSION, file.path);
      let extraction: FileExtraction | undefined;
      if (cached) {
        extraction = JSON.parse(gunzipSync(cached.data).toString()) as FileExtraction;
        stats.cached++;
      } else {
        const text = await input.readText(file.path);
        if (text === undefined) continue;
        extraction = await extractFile(file.path, text);
        if (!extraction) continue;
        put.run(file.digest, EXTRACTOR_VERSION, file.path, gzipSync(JSON.stringify(extraction)));
        stats.parsed++;
      }
      if (extraction.error) stats.errors++;
      files.push(extraction);
    }
    files.sort((a, b) => a.path.localeCompare(b.path));
    const edges = buildEdges(files);
    const data: CodeIndexData = { version: INDEX_SCHEMA_VERSION, extractorVersion: EXTRACTOR_VERSION, files, edges };
    const graph = new CodeGraph(data);
    stats.symbols = graph.symbols.size;
    stats.endpoints = graph.endpoints().length;
    stats.edges = edges.length;
    return { data, graph, stats };
  }
}
