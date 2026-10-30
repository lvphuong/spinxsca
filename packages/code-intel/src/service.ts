import { join } from 'node:path';
import type { ArtifactStore, CodeGraphView, CodeImpactReport, CodeIntelPort, SourceTree } from '@spinxsca/core';
import type { ArtifactRef, Digest, SnapshotFile, SourceSnapshot } from '@spinxsca/schemas';
import { IndexBuilder } from './builder';
import { CodeGraph } from './graph';
import { computeImpact } from './impact';
import type { CodeIndexData } from './types';

/** CodeIntelPort implementation: index artifacts are content-addressed JSON; the per-file cache lives in the state directory. */
export class CodeIntelService implements CodeIntelPort {
  private readonly cachePath: string;
  private readonly loaded = new Map<string, CodeGraphView>();

  constructor(stateDir: string) {
    this.cachePath = join(stateDir, 'code-intel.db');
  }

  async build(input: {
    snapshot: SourceSnapshot;
    files: readonly SnapshotFile[];
    source: SourceTree;
    artifacts: ArtifactStore;
    signal?: AbortSignal;
  }): Promise<{ artifact: ArtifactRef; graph: CodeGraphView; stats: Record<string, number> }> {
    const builder = new IndexBuilder(this.cachePath);
    try {
      const { data, graph, stats } = await builder.build({
        snapshot: input.snapshot,
        files: input.files,
        readText: (p) => input.source.readText(p),
        ...(input.signal ? { signal: input.signal } : {}),
      });
      const artifact = await input.artifacts.put(JSON.stringify(data), 'application/vnd.spinxsca.code-index+json');
      const view = asView(graph);
      this.loaded.set(artifact.digest, view);
      return { artifact, graph: view, stats: { ...stats } };
    } finally {
      builder.close();
    }
  }

  async load(artifacts: ArtifactStore, digest: Digest): Promise<CodeGraphView> {
    const cached = this.loaded.get(digest);
    if (cached) return cached;
    const data = JSON.parse(await artifacts.getText(digest)) as CodeIndexData;
    const view = asView(new CodeGraph(data));
    this.loaded.set(digest, view);
    return view;
  }

  impact(base: CodeGraphView | undefined, current: CodeGraphView, changedFiles: readonly string[]): CodeImpactReport {
    return computeImpact(base ? unwrap(base) : undefined, unwrap(current), changedFiles);
  }
}

const GRAPH = Symbol('graph');

function asView(graph: CodeGraph): CodeGraphView {
  const view: CodeGraphView & { [GRAPH]: CodeGraph } = {
    [GRAPH]: graph,
    get symbolCount() {
      return graph.symbols.size;
    },
    getSymbol: (key) => graph.getSymbol(key),
    symbolAt: (path, line) => graph.symbolAt(path, line),
    search: (query) => graph.search(query),
    callers: (key) => graph.callers(key),
    callees: (key) => graph.callees(key),
    endpoints: (filter) => graph.endpoints(filter),
    authContext: (id) => graph.authContext(id),
  };
  return view;
}

function unwrap(view: CodeGraphView): CodeGraph {
  const graph = (view as { [GRAPH]?: CodeGraph })[GRAPH];
  if (!graph) throw new Error('CodeGraphView was not produced by CodeIntelService');
  return graph;
}
