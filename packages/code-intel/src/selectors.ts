import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';
import { redactSecrets } from '@spinxsca/core';
import type { ShardSignal, SnapshotFile } from '@spinxsca/schemas';
import Database from 'better-sqlite3';
import { type SyntaxNode, walk } from './extractors/common';
import { getParser, languageOfPath } from './parser';
import type { Language } from './types';

/**
 * AST selectors for the shard planner (ADR-055): tree-sitter call nodes whose callee matches a sink
 * pattern. Unlike the lexical selectors they ignore comments and strings, so `os.system(` in a
 * docstring is not a signal. Results are cached per (content digest, selector version, path) in
 * the code-intel sqlite cache next to the extractor cache.
 */
export interface AstSelector {
  id: string;
  langs: readonly Language[];
  nodeKinds: readonly string[];
  callee: RegExp;
  weight: number;
}

export const AST_SELECTOR_VERSION = 'ast-selectors/v1';

const JS: Language[] = ['javascript', 'typescript', 'tsx'];

export const AST_SELECTORS: readonly AstSelector[] = [
  {
    id: 'rce.py_call',
    langs: ['python'],
    nodeKinds: ['call'],
    callee:
      /^(os\.system|os\.popen|subprocess\.(Popen|call|run|check_output|check_call)|eval|exec|__import__|compile)$/,
    weight: 3,
  },
  {
    id: 'rce.js_call',
    langs: JS,
    nodeKinds: ['call_expression', 'new_expression'],
    callee: /(child_process|\.exec(Sync)?$|^exec(Sync)?$|^eval$|^Function$|vm\.runIn|execFile(Sync)?$|spawn(Sync)?$)/,
    weight: 3,
  },
  {
    id: 'sqli.js_query',
    langs: JS,
    nodeKinds: ['call_expression'],
    callee: /\.(query|raw|execute|\$queryRawUnsafe|\$executeRawUnsafe)$/,
    weight: 2,
  },
  {
    id: 'sqli.py_execute',
    langs: ['python'],
    nodeKinds: ['call'],
    callee: /\.(execute|executemany|executescript|raw)$/,
    weight: 2,
  },
  {
    id: 'rce.java_exec',
    langs: ['java'],
    nodeKinds: ['method_invocation', 'object_creation_expression'],
    callee: /(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)/,
    weight: 3,
  },
  {
    id: 'deser.java',
    langs: ['java'],
    nodeKinds: ['method_invocation', 'object_creation_expression'],
    callee: /(ObjectInputStream|readObject|XMLDecoder)/,
    weight: 3,
  },
];

function calleeOf(node: SyntaxNode): string | undefined {
  switch (node.type) {
    case 'call':
    case 'call_expression':
      return node.childForFieldName('function')?.text;
    case 'new_expression':
      return node.childForFieldName('constructor')?.text;
    case 'method_invocation': {
      const object = node.childForFieldName('object')?.text;
      const name = node.childForFieldName('name')?.text;
      return object ? `${object}.${name ?? ''}` : name;
    }
    case 'object_creation_expression':
      return node.childForFieldName('type')?.text;
    default:
      return undefined;
  }
}

/** AST signals of one file (empty for languages without a grammar). */
export async function scanAst(path: string, text: string): Promise<ShardSignal[]> {
  const language = languageOfPath(path);
  if (!language) return [];
  const selectors = AST_SELECTORS.filter((s) => s.langs.includes(language));
  if (selectors.length === 0) return [];
  const parser = await getParser(language);
  const tree = parser.parse(text);
  const out: ShardSignal[] = [];
  try {
    if (!tree) return out;
    const lines = text.split('\n');
    walk(tree.rootNode, (node) => {
      for (const selector of selectors) {
        if (!selector.nodeKinds.includes(node.type)) continue;
        const callee = calleeOf(node)?.replace(/\s+/g, '');
        if (!callee || !selector.callee.test(callee)) continue;
        const line = node.startPosition.row + 1;
        out.push({
          path,
          line,
          selectorId: `ast.${selector.id}`,
          weight: selector.weight,
          evidence: redactSecrets((lines[line - 1] ?? '').trim()).text.slice(0, 200),
        });
      }
      return undefined;
    });
  } finally {
    tree?.delete();
    parser.delete();
  }
  return out;
}

/** Per-file cache of AST signals in the code-intel sqlite database. */
export class SignalCache {
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

  async signals(input: {
    files: readonly SnapshotFile[];
    readText: (path: string) => Promise<string | undefined>;
    signal?: AbortSignal;
  }): Promise<ShardSignal[]> {
    const get = this.db.prepare<[string, string, string], { data: Buffer }>(
      'SELECT data FROM file_cache WHERE digest = ? AND extractor = ? AND path = ?',
    );
    const put = this.db.prepare(
      'INSERT OR REPLACE INTO file_cache (digest, extractor, path, data) VALUES (?, ?, ?, ?)',
    );
    const out: ShardSignal[] = [];
    for (const file of input.files) {
      if (!languageOfPath(file.path)) continue;
      if (input.signal?.aborted) throw new Error('cancelled');
      const cached = get.get(file.digest, AST_SELECTOR_VERSION, file.path);
      if (cached) {
        out.push(...(JSON.parse(gunzipSync(cached.data).toString()) as ShardSignal[]));
        continue;
      }
      const text = await input.readText(file.path);
      if (text === undefined) continue;
      let signals: ShardSignal[] = [];
      try {
        signals = await scanAst(file.path, text);
      } catch {
        signals = [];
      }
      put.run(file.digest, AST_SELECTOR_VERSION, file.path, gzipSync(JSON.stringify(signals)));
      out.push(...signals);
    }
    return out;
  }
}
