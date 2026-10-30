import { createRequire } from 'node:module';
import { Parser, Language as TsLanguage } from 'web-tree-sitter';
import type { Language } from './types';

const require = createRequire(import.meta.url);

const GRAMMARS: Record<Language, string> = {
  javascript: 'tree-sitter-javascript/tree-sitter-javascript.wasm',
  typescript: 'tree-sitter-typescript/tree-sitter-typescript.wasm',
  tsx: 'tree-sitter-typescript/tree-sitter-tsx.wasm',
  python: 'tree-sitter-python/tree-sitter-python.wasm',
  java: 'tree-sitter-java/tree-sitter-java.wasm',
};

const EXTENSIONS: Record<string, Language> = {
  js: 'javascript',
  jsx: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  ts: 'typescript',
  mts: 'typescript',
  cts: 'typescript',
  tsx: 'tsx',
  py: 'python',
  java: 'java',
};

export function languageOfPath(path: string): Language | undefined {
  return EXTENSIONS[path.slice(path.lastIndexOf('.') + 1).toLowerCase()];
}

let initialized: Promise<void> | undefined;
const languages = new Map<Language, Promise<TsLanguage>>();

/** Lazily initialised parsers; one Language object per grammar is shared process-wide. */
export async function getParser(language: Language): Promise<Parser> {
  initialized ??= Parser.init();
  await initialized;
  let loading = languages.get(language);
  if (!loading) {
    loading = TsLanguage.load(require.resolve(GRAMMARS[language]));
    languages.set(language, loading);
  }
  const parser = new Parser();
  parser.setLanguage(await loading);
  return parser;
}
