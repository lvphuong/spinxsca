import type { Digest, Shard, ShardFile, ShardPlan, ShardSignal, SnapshotFile } from '@spinxsca/schemas';
import { sha256 } from '../ids';
import type { CodeGraphView } from '../ports';
import { SELECTOR_VERSION, selectorLanguageOf, skipForSelectors } from './selectors';

export interface PlanOptions {
  maxShards: number;
  maxFilesPerShard: number;
  /** Path segments that form a module (files of one module stay together). */
  groupDepth: number;
  includeZeroSignal: boolean;
}

export const DEFAULT_PLAN_OPTIONS: PlanOptions = {
  maxShards: 64,
  maxFilesPerShard: 40,
  groupDepth: 3,
  includeZeroSignal: false,
};

export interface PlanInput {
  files: readonly SnapshotFile[];
  signals: readonly ShardSignal[];
  /** Tokens of source one shard may hold (from the map model's effective window). */
  tokenBudget: number;
  mapModel: string;
  contentManifestDigest: Digest;
  /** Incremental or targeted scans: only these paths are candidates. */
  scope?: readonly string[];
  graph?: CodeGraphView;
  options?: Partial<PlanOptions>;
}

/** Token budget for one shard: a share of the map model's effective window, kept in a sane range. */
export function shardTokenBudget(effectiveWindow: number, ratio = 0.35): number {
  return Math.max(6_000, Math.min(60_000, Math.floor(effectiveWindow * ratio)));
}

/** Whether `auto` sharding should kick in for this candidate set. */
export function shouldShard(candidate: { files: number; tokens: number }, effectiveWindow: number): boolean {
  return candidate.files > 60 || candidate.tokens > 1.5 * effectiveWindow;
}

const MAX_NEIGHBORS = 40;
const MAX_SIGNALS_PER_SHARD = 400;

/**
 * Deterministic shard plan (ADR-055). Files with at least one signal are grouped by module (the first
 * `groupDepth` path segments), modules are ordered by score and packed greedily into shards under
 * the token budget without splitting a module unless it alone exceeds the budget. Every input order
 * is normalised, so the same snapshot and signals always give the same plan and shard digests.
 */
export function planShards(input: PlanInput): ShardPlan {
  const options = { ...DEFAULT_PLAN_OPTIONS, ...input.options };
  const scope = input.scope ? new Set(input.scope) : undefined;
  const byPath = new Map<string, ShardSignal[]>();
  for (const s of input.signals) {
    const list = byPath.get(s.path);
    if (list) list.push(s);
    else byPath.set(s.path, [s]);
  }
  let binaryOrLarge = 0;
  let zeroSignal = 0;
  const candidates: ShardFile[] = [];
  for (const f of [...input.files].sort((a, b) => a.path.localeCompare(b.path))) {
    if (scope && !scope.has(f.path)) continue;
    if (skipForSelectors(f.path, f.size) || !selectorLanguageOf(f.path)) {
      binaryOrLarge++;
      continue;
    }
    const signals = byPath.get(f.path) ?? [];
    if (signals.length === 0 && !options.includeZeroSignal) {
      zeroSignal++;
      continue;
    }
    const language = selectorLanguageOf(f.path);
    candidates.push({
      path: f.path,
      digest: f.digest,
      bytes: f.size,
      tokens: Math.ceil(f.size / 4),
      score: signals.reduce((n, s) => n + s.weight, 0),
      signals: signals.length,
      ...(language && language !== 'any' ? { language } : {}),
    });
  }

  // Modules ordered by total score, files inside by score; both tie-break on path.
  const modules = new Map<string, ShardFile[]>();
  for (const file of candidates) {
    const key = moduleOf(file.path, options.groupDepth);
    const list = modules.get(key);
    if (list) list.push(file);
    else modules.set(key, [file]);
  }
  const ordered = [...modules.entries()]
    .map(([module, files]) => ({
      module,
      files: files.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path)),
      score: files.reduce((n, f) => n + f.score, 0),
    }))
    .sort((a, b) => b.score - a.score || a.module.localeCompare(b.module));

  type Draft = { module: string; files: ShardFile[]; tokens: number; oversized: boolean };
  const drafts: Draft[] = [];
  let current: Draft | undefined;
  const close = () => {
    if (current?.files.length) drafts.push(current);
    current = undefined;
  };
  for (const m of ordered) {
    const moduleTokens = m.files.reduce((n, f) => n + f.tokens, 0);
    const fits = (d: Draft | undefined, tokens: number, files: number) =>
      d !== undefined && d.tokens + tokens <= input.tokenBudget && d.files.length + files <= options.maxFilesPerShard;
    if (moduleTokens <= input.tokenBudget && m.files.length <= options.maxFilesPerShard) {
      // Whole module into the current shard when it fits, otherwise into a fresh one.
      if (!fits(current, moduleTokens, m.files.length)) {
        close();
        current = { module: m.module, files: [], tokens: 0, oversized: false };
      }
      (current as Draft).files.push(...m.files);
      (current as Draft).tokens += moduleTokens;
      continue;
    }
    // The module alone exceeds the budget: split it file by file, oversized files alone.
    close();
    for (const file of m.files) {
      if (file.tokens > input.tokenBudget) {
        close();
        drafts.push({ module: m.module, files: [file], tokens: file.tokens, oversized: true });
        continue;
      }
      if (!fits(current, file.tokens, 1)) {
        close();
        current = { module: m.module, files: [], tokens: 0, oversized: false };
      }
      (current as Draft).files.push(file);
      (current as Draft).tokens += file.tokens;
    }
    close();
  }
  close();

  const ranked = drafts
    .map((d) => ({ ...d, score: d.files.reduce((n, f) => n + f.score, 0) }))
    .sort(
      (a, b) =>
        b.score - a.score ||
        a.module.localeCompare(b.module) ||
        (a.files[0]?.path ?? '').localeCompare(b.files[0]?.path ?? ''),
    );
  const kept = ranked.slice(0, options.maxShards);
  const overCap = ranked
    .slice(options.maxShards)
    .flatMap((d) => d.files.map((f) => f.path))
    .sort();
  const owned = new Set(kept.flatMap((d) => d.files.map((f) => f.path)));
  const allPaths = new Set(input.files.map((f) => f.path));

  const shards: Shard[] = kept.map((d, index) => {
    const paths = d.files.map((f) => f.path);
    const signals = paths
      .flatMap((p) => byPath.get(p) ?? [])
      .sort((a, b) => b.weight - a.weight || a.path.localeCompare(b.path) || (a.line ?? 0) - (b.line ?? 0))
      .slice(0, MAX_SIGNALS_PER_SHARD);
    return {
      shardId: `shard-${String(index + 1).padStart(4, '0')}`,
      digest: shardDigest(d.files),
      module: d.module,
      files: d.files,
      tokens: d.tokens,
      score: d.score,
      priority: index,
      neighbors: neighborsOf(paths, new Set(paths), input.graph, allPaths, owned),
      oversized: d.oversized,
      signals,
    };
  });
  return {
    version: 1,
    selectorVersion: SELECTOR_VERSION,
    contentManifestDigest: input.contentManifestDigest,
    tokenBudget: input.tokenBudget,
    mapModel: input.mapModel,
    shards,
    excluded: { zeroSignal, overCap, binaryOrLarge },
    stats: {
      files: input.files.length,
      candidateFiles: candidates.length,
      totalTokens: candidates.reduce((n, f) => n + f.tokens, 0),
      maxShardTokens: shards.reduce((n, s) => Math.max(n, s.tokens), 0),
      modules: modules.size,
      signals: input.signals.length,
    },
  };
}

export function moduleOf(path: string, depth: number): string {
  const segments = path.split('/');
  segments.pop();
  if (segments.length === 0) return '(root)';
  return segments.slice(0, depth).join('/');
}

/** Content identity of a shard: selector version plus every owned file's path and digest. */
export function shardDigest(files: readonly ShardFile[]): Digest {
  const body = [...files]
    .map((f) => `${f.path}\0${f.digest}`)
    .sort()
    .join('\n');
  return sha256(`${SELECTOR_VERSION}\n${body}`);
}

const SOURCE_EXTENSIONS = ['ts', 'tsx', 'js', 'jsx', 'mjs', 'cjs', 'py', 'java'];

/** Files the shard reaches in one hop (imports and callees), excluding files it owns. */
function neighborsOf(
  paths: readonly string[],
  ownedHere: ReadonlySet<string>,
  graph: CodeGraphView | undefined,
  allPaths: ReadonlySet<string>,
  _ownedAnywhere: ReadonlySet<string>,
): string[] {
  if (!graph) return [];
  const counts = new Map<string, number>();
  const bump = (p: string | undefined) => {
    if (!p || ownedHere.has(p) || !allPaths.has(p)) return;
    counts.set(p, (counts.get(p) ?? 0) + 1);
  };
  for (const path of paths) {
    for (const imp of graph.importsOf?.(path) ?? []) {
      if (!imp.specifier.startsWith('.')) continue;
      bump(resolveRelative(path, imp.specifier, allPaths));
    }
    for (const symbol of graph.search({ path, limit: 200 })) {
      for (const edge of graph.callees(symbol.key)) bump(graph.getSymbol(edge.to)?.path);
    }
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, MAX_NEIGHBORS)
    .map(([p]) => p);
}

function resolveRelative(from: string, specifier: string, allPaths: ReadonlySet<string>): string | undefined {
  const dir = from.split('/').slice(0, -1);
  for (const part of specifier.split('/')) {
    if (part === '.' || part === '') continue;
    if (part === '..') dir.pop();
    else dir.push(part);
  }
  const base = dir.join('/');
  if (allPaths.has(base)) return base;
  for (const ext of SOURCE_EXTENSIONS) {
    if (allPaths.has(`${base}.${ext}`)) return `${base}.${ext}`;
    if (allPaths.has(`${base}/index.${ext}`)) return `${base}/index.${ext}`;
  }
  // Python packages: `from .orders import x` -> orders.py or orders/__init__.py
  if (allPaths.has(`${base}/__init__.py`)) return `${base}/__init__.py`;
  return undefined;
}
