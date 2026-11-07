import type { ShardSignal, SnapshotFile } from '@spinxsca/schemas';
import type { ResourceMatrix } from '../census/resource-matrix';
import type { CandidateDraft, CodeGraphView, CodeIntelPort } from '../ports';
import { scanLexical, skipForSelectors } from './selectors';

/**
 * Signal sources for the shard planner (ADR-055). Every source is deterministic and already
 * computed for other purposes (index, census, scanners) except the lexical and AST selectors.
 */
export function indexSignals(graph: CodeGraphView): ShardSignal[] {
  const out: ShardSignal[] = [];
  for (const e of graph.endpoints()) {
    out.push({
      path: e.path,
      line: e.line,
      selectorId: 'index.endpoint',
      weight: 3,
      evidence: `${e.method} ${e.route}`.slice(0, 200),
    });
    for (const c of e.controls)
      out.push({
        path: c.path,
        line: c.line,
        selectorId: 'index.control',
        weight: 2,
        evidence: `${c.kind} ${c.name}`.slice(0, 200),
      });
  }
  return out;
}

export function censusSignals(matrix: ResourceMatrix): ShardSignal[] {
  const out: ShardSignal[] = [];
  for (const g of matrix.groups) {
    for (const r of g.rows) {
      if (!r.flagged) continue;
      out.push({
        path: r.path,
        line: r.line,
        selectorId: 'census.flagged',
        weight: 4,
        evidence:
          `${r.method} ${r.route}: sibling in ${g.group} has authorization or a scoped query, this row has neither`.slice(
            0,
            200,
          ),
      });
    }
  }
  for (const s of matrix.sites) {
    if (s.scopedBy !== 'none' && s.scopedBy !== 'unknown') continue;
    out.push({
      path: s.path,
      line: s.line,
      selectorId: 'census.data_access',
      weight: 2,
      evidence: `${s.callee} ${s.operation} scope=${s.scopedBy}`.slice(0, 200),
    });
  }
  return out;
}

export function scannerSignals(
  drafts: ReadonlyArray<Pick<CandidateDraft, 'category' | 'locations' | 'title'>>,
): ShardSignal[] {
  const out: ShardSignal[] = [];
  for (const d of drafts) {
    if (/SECRET/i.test(d.category)) continue;
    const primary = d.locations.find((l) => l.role === 'primary') ?? d.locations[0];
    if (!primary) continue;
    out.push({
      path: primary.path,
      line: primary.startLine,
      selectorId: `scanner.${d.category.toLowerCase()}`.slice(0, 80),
      weight: 2,
      evidence: d.title.slice(0, 200),
    });
  }
  return out;
}

export interface CollectSignalsInput {
  files: readonly SnapshotFile[];
  readText: (path: string) => Promise<string | undefined>;
  graph?: CodeGraphView;
  matrix?: ResourceMatrix;
  scannerDrafts?: ReadonlyArray<Pick<CandidateDraft, 'category' | 'locations' | 'title'>>;
  /** AST selectors (tree-sitter) live in code-intel and are optional. */
  codeIntel?: Pick<CodeIntelPort, 'signals'>;
  signal?: AbortSignal;
}

/** Every signal source combined; the result is sorted so plans are reproducible. */
export async function collectSignals(input: CollectSignalsInput): Promise<ShardSignal[]> {
  const out: ShardSignal[] = [];
  if (input.graph) out.push(...indexSignals(input.graph));
  if (input.matrix) out.push(...censusSignals(input.matrix));
  if (input.scannerDrafts) out.push(...scannerSignals(input.scannerDrafts));
  const scannable = input.files.filter((f) => !skipForSelectors(f.path, f.size));
  for (const file of scannable) {
    if (input.signal?.aborted) throw new Error('cancelled');
    const text = await input.readText(file.path);
    if (text === undefined || text.includes('\u0000')) continue;
    out.push(...scanLexical(file.path, text));
  }
  if (input.codeIntel?.signals) {
    out.push(
      ...(await input.codeIntel.signals({
        files: scannable,
        readText: input.readText,
        ...(input.signal ? { signal: input.signal } : {}),
      })),
    );
  }
  return out.sort(
    (a, b) => a.path.localeCompare(b.path) || (a.line ?? 0) - (b.line ?? 0) || a.selectorId.localeCompare(b.selectorId),
  );
}
