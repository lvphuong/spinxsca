import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';

/**
 * Code search backends (ADR-056). ripgrep on PATH is used when the source tree is a real directory;
 * otherwise a streaming scan reads files one at a time. Neither keeps file contents around beyond
 * the small LRU shared with `read_file`, so searching a 300k-line repository does not pin it in RAM.
 */
export interface SearchQuery {
  query: string;
  pathPrefix?: string;
  ignoreCase?: boolean;
  limit: number;
  offset?: number;
  /** Paths the caller may see (snapshot ∩ data policy). */
  allowed: ReadonlySet<string>;
}

export interface SearchHit {
  path: string;
  line: number;
  text: string;
}

export interface SearchResult {
  hits: SearchHit[];
  /** More hits exist beyond `offset + limit`. */
  truncated: boolean;
  backend: 'ripgrep' | 'scan';
}

export interface Searcher {
  search(q: SearchQuery): Promise<SearchResult>;
}

/** Bounded cache of split files shared by `read_file` and the scanning searcher. */
export class LruLineCache {
  private readonly entries = new Map<string, { lines: string[] | undefined; bytes: number }>();
  private bytes = 0;

  constructor(
    private readonly maxFiles = 128,
    private readonly maxBytes = 32 * 1024 * 1024,
  ) {}

  has(path: string): boolean {
    return this.entries.has(path);
  }

  get(path: string): string[] | undefined {
    const entry = this.entries.get(path);
    if (!entry) return undefined;
    // Refresh recency.
    this.entries.delete(path);
    this.entries.set(path, entry);
    return entry.lines;
  }

  set(path: string, lines: string[] | undefined): void {
    const bytes = lines ? lines.reduce((n, l) => n + l.length + 1, 0) : 0;
    const old = this.entries.get(path);
    if (old) this.bytes -= old.bytes;
    this.entries.set(path, { lines, bytes });
    this.bytes += bytes;
    while (this.entries.size > this.maxFiles || this.bytes > this.maxBytes) {
      const oldest = this.entries.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.bytes -= this.entries.get(oldest)?.bytes ?? 0;
      this.entries.delete(oldest);
    }
  }

  get size(): number {
    return this.entries.size;
  }
}

let ripgrep: Promise<string | undefined> | undefined;

/** Path of a usable `rg` binary on PATH, probed once per process. */
export function ripgrepPath(): Promise<string | undefined> {
  ripgrep ??= new Promise((done) => {
    execFile('rg', ['--version'], { timeout: 3_000 }, (err) => done(err ? undefined : 'rg'));
  });
  return ripgrep;
}

const RG_MAX_PER_FILE = 50;

export interface SearcherOptions {
  /** Absolute root of the source tree; ripgrep is only used when it exists on disk. */
  root: string;
  readLines: (path: string) => Promise<string[] | undefined>;
  /** Candidate paths for the scanning backend (in search order). */
  paths: readonly string[];
  rgPath?: string | Promise<string | undefined>;
}

export function createSearcher(options: SearcherOptions): Searcher {
  const rg = options.rgPath ?? (existsSync(options.root) ? ripgrepPath() : undefined);
  return {
    async search(q) {
      const binary = await rg;
      if (binary) {
        try {
          return await searchWithRipgrep(binary, options.root, q);
        } catch {
          // Fall through to the scanning backend (ripgrep missing, too many matches, odd encodings).
        }
      }
      return searchByScanning(options.paths, options.readLines, q);
    },
  };
}

async function searchWithRipgrep(binary: string, root: string, q: SearchQuery): Promise<SearchResult> {
  const args = ['--json', '-F', '-n', '--no-messages', '--max-count', String(RG_MAX_PER_FILE), '--max-filesize', '1M'];
  if (q.ignoreCase) args.push('-i');
  if (q.pathPrefix) args.push('-g', `${q.pathPrefix.replace(/\/+$/, '')}/**`, '-g', q.pathPrefix);
  args.push('-e', q.query, '--', root);
  const stdout = await new Promise<string>((done, fail) => {
    execFile(binary, args, { maxBuffer: 32 * 1024 * 1024, timeout: 30_000 }, (err, out) => {
      // Exit code 1 means "no matches"; anything else is a real failure.
      if (err && (err as { code?: number | string }).code !== 1) fail(err);
      else done(out);
    });
  });
  const all: SearchHit[] = [];
  for (const line of stdout.split('\n')) {
    if (!line) continue;
    let event: { type?: string; data?: { path?: { text?: string }; line_number?: number; lines?: { text?: string } } };
    try {
      event = JSON.parse(line);
    } catch {
      continue;
    }
    if (event.type !== 'match' || !event.data?.path?.text) continue;
    const path = relative(root, resolve(event.data.path.text)).split(sep).join('/');
    if (!q.allowed.has(path)) continue;
    if (q.pathPrefix && !path.startsWith(q.pathPrefix)) continue;
    all.push({ path, line: event.data.line_number ?? 0, text: (event.data.lines?.text ?? '').replace(/\r?\n$/, '') });
  }
  all.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line);
  const start = q.offset ?? 0;
  return { hits: all.slice(start, start + q.limit), truncated: all.length > start + q.limit, backend: 'ripgrep' };
}

async function searchByScanning(
  paths: readonly string[],
  readLines: (path: string) => Promise<string[] | undefined>,
  q: SearchQuery,
): Promise<SearchResult> {
  const needle = q.ignoreCase ? q.query.toLowerCase() : q.query;
  const start = q.offset ?? 0;
  const hits: SearchHit[] = [];
  let seen = 0;
  let truncated = false;
  for (const path of paths) {
    if (!q.allowed.has(path)) continue;
    if (q.pathPrefix && !path.startsWith(q.pathPrefix)) continue;
    const lines = await readLines(path);
    if (!lines) continue;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] as string;
      if (!(q.ignoreCase ? line.toLowerCase() : line).includes(needle)) continue;
      if (seen++ < start) continue;
      if (hits.length >= q.limit) {
        truncated = true;
        return { hits, truncated, backend: 'scan' };
      }
      hits.push({ path, line: i + 1, text: line });
    }
  }
  return { hits, truncated, backend: 'scan' };
}
