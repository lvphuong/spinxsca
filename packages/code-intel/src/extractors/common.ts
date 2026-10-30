import { sha256Hex } from '@spinxsca/core';
import type { Node } from 'web-tree-sitter';
import type { ControlKind, FileExtraction, Language, SymbolKind, SymbolRecord } from '../types';

export type SyntaxNode = Node;

export function emptyExtraction(path: string, language: Language): FileExtraction {
  return { path, language, symbols: [], imports: [], calls: [], endpoints: [], globalControls: [], mounts: [] };
}

export function line(node: SyntaxNode): number {
  return node.startPosition.row + 1;
}

export function endLine(node: SyntaxNode): number {
  return node.endPosition.row + 1;
}

export function symbolKey(path: string, qualifiedName: string): string {
  return `${path}::${qualifiedName}`;
}

/**
 * Hash of the implementation with comments and whitespace removed. Unlike the fingerprint shape,
 * literal values are kept: changing a role name or a query string is a change for impact analysis.
 */
export function contentHash(text: string, language: Language): string {
  let stripped = text.replace(/\/\*[\s\S]*?\*\//g, '');
  stripped = language === 'python' ? stripped.replace(/#.*$/gm, '') : stripped.replace(/(^|[^:\\'"`])\/\/.*$/gm, '$1');
  return sha256Hex(stripped.replace(/\s+/g, '')).slice(0, 16);
}

export function makeSymbol(input: {
  path: string;
  language: Language;
  name: string;
  qualifiedName: string;
  kind: SymbolKind;
  node: SyntaxNode;
  owner?: string;
  exported: boolean;
}): SymbolRecord {
  return {
    key: symbolKey(input.path, input.qualifiedName),
    path: input.path,
    name: input.name,
    qualifiedName: input.qualifiedName,
    kind: input.kind,
    startLine: line(input.node),
    endLine: endLine(input.node),
    contentHash: contentHash(input.node.text, input.language),
    ...(input.owner ? { owner: input.owner } : {}),
    exported: input.exported,
  };
}

/** Pre-order traversal with the ability to skip subtrees. */
export function walk(node: SyntaxNode, visit: (node: SyntaxNode) => boolean | undefined): void {
  const stack: SyntaxNode[] = [node];
  while (stack.length) {
    const current = stack.pop() as SyntaxNode;
    if (visit(current) === false) continue;
    for (let i = current.namedChildCount - 1; i >= 0; i--) {
      const child = current.namedChild(i);
      if (child) stack.push(child);
    }
  }
}

export function stringValue(node: SyntaxNode | null | undefined): string | undefined {
  if (!node) return undefined;
  if (
    node.type === 'string' ||
    node.type === 'string_literal' ||
    node.type === 'template_string' ||
    node.type === 'concatenated_string'
  ) {
    const text = node.text;
    if (node.type === 'template_string' && text.includes('${')) return undefined;
    return text.replace(/^[rRbBfFuU]*(["'`])/, '').replace(/(["'`])$/, '');
  }
  return undefined;
}

const AUTHZ = /(authoriz|permission|role|policy|owner|admin|acl|rbac|can[A-Z_]|allow|scope|tenant)/i;
const AUTHN =
  /(auth|login|jwt|token|session|passport|bearer|api[_-]?key|identity|signed[_-]?in|logged|current[_-]?user|get[_-]?user|verify[_-]?user|principal)/i;
const VALIDATION = /(valid|sanitiz|schema|celebrate|joi|zod|yup)/i;
const RATE = /(rate[_-]?limit|throttl|slow[_-]?down)/i;

/** Classifies a middleware/guard/dependency by name. Heuristic; the agent verifies the body. */
export function classifyControl(name: string): ControlKind {
  if (AUTHZ.test(name)) return 'AUTHORIZATION';
  if (AUTHN.test(name)) return 'AUTHENTICATION';
  if (VALIDATION.test(name)) return 'VALIDATION';
  if (RATE.test(name)) return 'RATE_LIMIT';
  return 'OTHER';
}

export function isControlName(name: string): boolean {
  return classifyControl(name) !== 'OTHER';
}

export function lastSegment(callee: string): string {
  const cleaned = callee.replace(/\(.*$/s, '');
  const parts = cleaned.split('.');
  return (parts[parts.length - 1] ?? cleaned).trim();
}

export function endpointId(path: string, method: string, route: string, lineNo: number): string {
  return `${path}#${method} ${route}@${lineNo}`;
}

export function joinRoute(prefix: string | undefined, route: string): string {
  if (!prefix) return route || '/';
  const joined = `${prefix.replace(/\/+$/, '')}/${route.replace(/^\/+/, '')}`;
  return joined.replace(/\/+$/, '') || '/';
}

export function pushFieldType(out: FileExtraction, entry: { owner: string; field: string; type: string }): void {
  if (!out.fieldTypes) out.fieldTypes = [];
  out.fieldTypes.push(entry);
}
