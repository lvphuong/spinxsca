import type { FingerprintAnchor } from '@spinxsca/schemas';
import { sha256Hex } from './ids';
import { FINGERPRINT_ALGORITHM } from './version';

export type SourceLanguage = 'js' | 'python' | 'java' | 'generic';

export function languageOf(path: string): SourceLanguage {
  const ext = path.slice(path.lastIndexOf('.') + 1).toLowerCase();
  if (['js', 'jsx', 'mjs', 'cjs', 'ts', 'tsx', 'mts', 'cts'].includes(ext)) return 'js';
  if (ext === 'py') return 'python';
  if (['java', 'kt', 'kts'].includes(ext)) return 'java';
  return 'generic';
}

const MAX_SHAPE_LINES = 20;
const MAX_SYMBOL_LOOKBACK = 300;

const JS_ROUTE = /\b(?:router|app|server|api|route)\.(get|post|put|patch|delete|all|use)\s*\(\s*(['"`])([^'"`]+)\2/i;
const JS_FUNCTION = /\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(/;
const JS_BINDING =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|[A-Za-z_$][\w$]*\s*=>)/;
const JS_METHOD =
  /^\s*(?:(?:public|private|protected|static|async|override|readonly|get|set)\s+)*([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?::\s*[^{=]+)?\{\s*$/;
const JS_KEYWORDS = new Set(['if', 'for', 'while', 'switch', 'catch', 'function', 'return', 'with']);
const PY_DEF = /^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/;
const PY_CLASS = /^(\s*)class\s+([A-Za-z_]\w*)/;
const JAVA_METHOD =
  /^\s*(?:(?:public|private|protected|static|final|synchronized|abstract|default)\s+)+[\w<>[\],.?\s]+?\s+([A-Za-z_]\w*)\s*\(/;

/**
 * Heuristic enclosing symbol until the code-intel index exists (phase 2). Returned keys are
 * prefixed with "heuristic:" so they are never confused with resolved symbol keys.
 */
export function enclosingSymbol(lines: readonly string[], startLine: number, language: SourceLanguage): string {
  const from = Math.min(startLine, lines.length) - 1;
  const stop = Math.max(0, from - MAX_SYMBOL_LOOKBACK);
  const targetIndent = indentOf(lines[from] ?? '');
  for (let i = from; i >= stop; i--) {
    const line = lines[i] ?? '';
    if (language === 'js') {
      const route = JS_ROUTE.exec(line);
      if (route) return `heuristic:route:${route[1]?.toUpperCase()} ${route[3]}`;
      const name = JS_FUNCTION.exec(line)?.[1] ?? JS_BINDING.exec(line)?.[1] ?? JS_METHOD.exec(line)?.[1];
      if (name && !JS_KEYWORDS.has(name)) return `heuristic:${name}`;
    } else if (language === 'python') {
      const def = PY_DEF.exec(line) ?? PY_CLASS.exec(line);
      if (def && (i === from || (def[1] ?? '').length < targetIndent)) return `heuristic:${def[2]}`;
    } else if (language === 'java') {
      const method = JAVA_METHOD.exec(line);
      if (method?.[1] && !JS_KEYWORDS.has(method[1])) return `heuristic:${method[1]}`;
    }
  }
  return '';
}

function indentOf(line: string): number {
  return /^\s*/.exec(line)?.[0].length ?? 0;
}

/**
 * Normalizes code so that whitespace, comments, literal values and line moves do not change the
 * fingerprint, while a different sink expression does.
 */
export function normalizeCodeShape(snippet: string, language: SourceLanguage): string {
  let text = snippet.replace(/\/\*[\s\S]*?\*\//g, '');
  text = language === 'python' ? text.replace(/#.*$/gm, '') : text.replace(/(^|[^:\\])\/\/.*$/gm, '$1');
  return text
    .replace(/(["'`])(?:\\.|(?!\1)[^\\])*\1/g, '$1$1')
    .replace(/\b\d+(?:\.\d+)?\b/g, '0')
    .replace(/[\s;]+/g, '');
}

export function anchorFor(input: {
  path: string;
  startLine: number;
  endLine: number;
  fileText: string | undefined;
}): Omit<FingerprintAnchor, 'instance'> {
  const language = languageOf(input.path);
  if (input.fileText === undefined) {
    // Without source text fall back to a path + line anchor; such fingerprints do not survive edits.
    return { path: input.path, symbol: '', shape: `line:${input.startLine}` };
  }
  const lines = input.fileText.split(/\r?\n/);
  const end = Math.min(input.endLine, input.startLine + MAX_SHAPE_LINES - 1);
  const snippet = lines.slice(input.startLine - 1, end).join('\n');
  return {
    path: input.path,
    symbol: enclosingSymbol(lines, input.startLine, language),
    shape: sha256Hex(normalizeCodeShape(snippet, language)).slice(0, 16),
  };
}

export function semanticFingerprint(input: {
  repositoryId: string;
  category: string;
  ruleFamily: string;
  anchor: FingerprintAnchor;
}): string {
  const { anchor } = input;
  const material = [
    FINGERPRINT_ALGORITHM,
    input.repositoryId,
    input.category,
    input.ruleFamily,
    anchor.path,
    anchor.symbol,
    anchor.shape,
    String(anchor.instance),
  ].join('\u0000');
  return `spx1:${sha256Hex(material).slice(0, 32)}`;
}

/**
 * Assigns an ordinal to drafts whose anchors are otherwise identical (same sink expression repeated
 * in one function), ordered by line, so each keeps a distinct and stable fingerprint.
 */
export function assignInstances<T extends { key: string; line: number }>(items: readonly T[]): Map<T, number> {
  const byKey = new Map<string, T[]>();
  for (const item of items) {
    const list = byKey.get(item.key) ?? [];
    list.push(item);
    byKey.set(item.key, list);
  }
  const result = new Map<T, number>();
  for (const list of byKey.values()) {
    list.sort((a, b) => a.line - b.line);
    list.forEach((item, index) => {
      result.set(item, index);
    });
  }
  return result;
}
