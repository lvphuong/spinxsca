import type { ControlRef, FileExtraction, Language, SymbolRecord } from '../types';
import {
  classifyControl,
  emptyExtraction,
  endpointId,
  joinRoute,
  lastSegment,
  line,
  makeSymbol,
  pushFieldType,
  type SyntaxNode,
  stringValue,
  symbolKey,
  walk,
} from './common';

const MAPPINGS: Record<string, string> = {
  GetMapping: 'GET',
  PostMapping: 'POST',
  PutMapping: 'PUT',
  PatchMapping: 'PATCH',
  DeleteMapping: 'DELETE',
  RequestMapping: 'ANY',
};
const SECURITY_ANNOTATIONS =
  /^(PreAuthorize|PostAuthorize|Secured|RolesAllowed|PermitAll|DenyAll|Authenticated|RequiresRoles|RequiresPermissions)$/;

/** Java extraction: classes, methods, imports, invocations, Spring MVC endpoints with security annotations. */
export function extractJava(path: string, language: Language, root: SyntaxNode): FileExtraction {
  const out = emptyExtraction(path, language);
  const moduleKey = symbolKey(path, '<module>');
  out.symbols.push({
    key: moduleKey,
    path,
    name: '<module>',
    qualifiedName: '<module>',
    kind: 'module',
    startLine: 1,
    endLine: root.endPosition.row + 1,
    contentHash: '',
    exported: false,
  });
  const symbolByNode = new Map<number, SymbolRecord>();

  const annotationsOf = (node: SyntaxNode): Array<{ name: string; args: SyntaxNode[]; node: SyntaxNode }> => {
    const modifiers = node.namedChildren.find((c) => c.type === 'modifiers');
    return (modifiers?.namedChildren ?? [])
      .filter((c) => c.type === 'annotation' || c.type === 'marker_annotation')
      .map((a) => ({
        name: a.childForFieldName('name')?.text ?? '',
        args: a.childForFieldName('arguments')?.namedChildren ?? [],
        node: a,
      }));
  };
  const mappingRoute = (args: SyntaxNode[]): string => {
    const direct = stringValue(args[0]);
    if (direct !== undefined) return direct;
    for (const pair of args.filter((a) => a.type === 'element_value_pair')) {
      const key = pair.childForFieldName('key')?.text;
      if (key === 'value' || key === 'path') {
        const value = pair.childForFieldName('value');
        const str = stringValue(value) ?? stringValue(value?.namedChildren[0]);
        if (str !== undefined) return str;
      }
    }
    return '';
  };
  const mappingMethod = (args: SyntaxNode[]): string | undefined => {
    const pair = args.find((a) => a.type === 'element_value_pair' && a.childForFieldName('key')?.text === 'method');
    const text = pair?.childForFieldName('value')?.text ?? '';
    return /RequestMethod\.(\w+)/.exec(text)?.[1]?.toUpperCase();
  };

  const declare = (node: SyntaxNode, prefix: string, owner?: string): void => {
    for (const child of node.namedChildren) {
      if (/^(class|interface|enum|record)_declaration$/.test(child.type)) {
        const name = child.childForFieldName('name')?.text ?? 'Anonymous';
        const qualified = prefix ? `${prefix}.${name}` : name;
        const symbol = makeSymbol({
          path,
          language,
          name,
          qualifiedName: qualified,
          kind: 'class',
          node: child,
          exported: /public/.test(child.namedChildren.find((c) => c.type === 'modifiers')?.text ?? ''),
        });
        out.symbols.push(symbol);
        symbolByNode.set(child.id, symbol);
        const body = child.childForFieldName('body');
        if (body) declare(body, qualified, symbol.key);
      } else if (child.type === 'field_declaration' && owner) {
        const type = child.childForFieldName('type')?.text;
        for (const declarator of child.namedChildren.filter((c) => c.type === 'variable_declarator')) {
          const field = declarator.childForFieldName('name')?.text;
          if (field && type) pushFieldType(out, { owner, field, type: type.replace(/<.*$/, '') });
        }
      } else if (child.type === 'method_declaration' || child.type === 'constructor_declaration') {
        const name = child.childForFieldName('name')?.text ?? 'method';
        const qualified = prefix ? `${prefix}.${name}` : name;
        const symbol = makeSymbol({
          path,
          language,
          name,
          qualifiedName: qualified,
          kind: 'method',
          node: child,
          ...(owner ? { owner } : {}),
          exported: /public/.test(child.namedChildren.find((c) => c.type === 'modifiers')?.text ?? ''),
        });
        out.symbols.push(symbol);
        symbolByNode.set(child.id, symbol);
      }
    }
  };
  declare(root, '');
  const ordered = out.symbols
    .filter((s) => s.kind !== 'module')
    .sort((a, b) => a.startLine - b.startLine || b.endLine - a.endLine);
  const enclosing = (lineNo: number): SymbolRecord => {
    let best: SymbolRecord | undefined;
    for (const s of ordered) {
      if (
        s.startLine <= lineNo &&
        s.endLine >= lineNo &&
        (!best || s.endLine - s.startLine <= best.endLine - best.startLine)
      )
        best = s;
    }
    return best ?? (out.symbols[0] as SymbolRecord);
  };

  walk(root, (n) => {
    if (n.type === 'import_declaration') {
      const name = n.namedChildren.find((c) => c.type === 'scoped_identifier' || c.type === 'identifier')?.text ?? '';
      const wildcard = n.text.includes('.*');
      out.imports.push({
        path,
        specifier: name,
        names: [{ imported: wildcard ? '*' : lastSegment(name), local: wildcard ? '*' : lastSegment(name) }],
        line: line(n),
      });
      return false;
    }
    if (n.type === 'method_invocation') {
      const object = n.childForFieldName('object')?.text;
      const name = n.childForFieldName('name')?.text ?? '';
      const callee = object ? `${object}.${name}`.replace(/\s+/g, '') : name;
      out.calls.push({ path, line: line(n), callerKey: enclosing(line(n)).key, callee, name });
    }
    return true;
  });

  for (const cls of root.descendantsOfType('class_declaration')) {
    const annotations = annotationsOf(cls);
    if (!annotations.some((a) => /^(RestController|Controller)$/.test(a.name))) continue;
    const base = annotations.find((a) => a.name === 'RequestMapping');
    const prefix = base ? mappingRoute(base.args) : '';
    const classControls: ControlRef[] = annotations
      .filter((a) => SECURITY_ANNOTATIONS.test(a.name))
      .map((a) => ({
        ref: a.node.text,
        name: a.name,
        kind:
          classifyControl(`${a.name} ${a.node.text}`) === 'OTHER'
            ? 'AUTHORIZATION'
            : classifyControl(`${a.name} ${a.node.text}`),
        source: 'annotation' as const,
        path,
        line: line(a.node),
      }));
    for (const member of cls.childForFieldName('body')?.namedChildren ?? []) {
      if (member.type !== 'method_declaration') continue;
      const memberAnnotations = annotationsOf(member);
      const mapping = memberAnnotations.find((a) => MAPPINGS[a.name]);
      if (!mapping) continue;
      const method =
        MAPPINGS[mapping.name] === 'ANY' ? (mappingMethod(mapping.args) ?? 'ANY') : (MAPPINGS[mapping.name] as string);
      const route = joinRoute(prefix, mappingRoute(mapping.args));
      const symbol = symbolByNode.get(member.id);
      const controls = [
        ...classControls,
        ...memberAnnotations
          .filter((a) => SECURITY_ANNOTATIONS.test(a.name))
          .map((a) => ({
            ref: a.node.text,
            name: a.name,
            kind: 'AUTHORIZATION' as const,
            source: 'annotation' as const,
            path,
            line: line(a.node),
          })),
      ];
      out.endpoints.push({
        id: endpointId(path, method, route, line(member)),
        path,
        line: line(member),
        method,
        route,
        framework: 'spring',
        handlers: symbol ? [symbol.key] : [],
        controls,
      });
    }
  }
  return out;
}
