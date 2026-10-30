import type { ControlRef, FileExtraction, Language, SymbolRecord } from '../types';
import {
  classifyControl,
  emptyExtraction,
  endpointId,
  lastSegment,
  line,
  makeSymbol,
  type SyntaxNode,
  stringValue,
  symbolKey,
  walk,
} from './common';

const HTTP = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'route', 'api_route', 'websocket']);
const ROUTE_OWNERS = /^(app|router|bp|blueprint|api|application|[a-z_]*_bp|[a-z_]*router)$/i;

/** Python extraction: functions, classes, methods, imports, calls, Flask/FastAPI routes with dependencies. */
export function extractPython(path: string, language: Language, root: SyntaxNode): FileExtraction {
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
  const declare = (node: SyntaxNode, qualifiedPrefix: string, owner?: string): void => {
    for (const child of node.namedChildren) {
      let target = child;
      if (child.type === 'decorated_definition') target = child.childForFieldName('definition') ?? child;
      if (target.type === 'function_definition' || target.type === 'class_definition') {
        const name = target.childForFieldName('name')?.text ?? 'anonymous';
        const qualified = qualifiedPrefix ? `${qualifiedPrefix}.${name}` : name;
        const symbol = makeSymbol({
          path,
          language,
          name,
          qualifiedName: qualified,
          kind: target.type === 'class_definition' ? 'class' : owner ? 'method' : 'function',
          node: child,
          ...(owner ? { owner } : {}),
          exported: !name.startsWith('_'),
        });
        out.symbols.push(symbol);
        symbolByNode.set(target.id, symbol);
        const body = target.childForFieldName('body');
        if (body) declare(body, qualified, target.type === 'class_definition' ? symbol.key : owner);
      } else if (child.type === 'if_statement' || child.type === 'try_statement' || child.type === 'block') {
        declare(child, qualifiedPrefix, owner);
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
    if (n.type === 'import_statement') {
      for (const item of n.namedChildren) {
        if (item.type === 'dotted_name')
          out.imports.push({ path, specifier: item.text, names: [{ imported: '*', local: item.text }], line: line(n) });
        else if (item.type === 'aliased_import') {
          const name = item.childForFieldName('name')?.text ?? '';
          out.imports.push({
            path,
            specifier: name,
            names: [{ imported: '*', local: item.childForFieldName('alias')?.text ?? name }],
            line: line(n),
          });
        }
      }
      return false;
    }
    if (n.type === 'import_from_statement') {
      const module = n.childForFieldName('module_name')?.text ?? '';
      const names: Array<{ imported: string; local: string }> = [];
      for (const item of n.namedChildren.slice(1)) {
        if (item.type === 'dotted_name') names.push({ imported: item.text, local: item.text });
        else if (item.type === 'aliased_import') {
          const imported = item.childForFieldName('name')?.text ?? '';
          names.push({ imported, local: item.childForFieldName('alias')?.text ?? imported });
        } else if (item.type === 'wildcard_import') names.push({ imported: '*', local: '*' });
      }
      out.imports.push({ path, specifier: module, names, line: line(n) });
      return false;
    }
    if (n.type === 'call') {
      const fn = n.childForFieldName('function');
      if (fn) {
        const callee = fn.text.replace(/\s+/g, '');
        out.calls.push({ path, line: line(n), callerKey: enclosing(line(n)).key, callee, name: lastSegment(callee) });
      }
    }
    return true;
  });

  // Routes: decorated functions.
  for (const decorated of root.descendantsOfType('decorated_definition')) {
    const definition = decorated.childForFieldName('definition');
    if (definition?.type !== 'function_definition') continue;
    const symbol = symbolByNode.get(definition.id);
    for (const decorator of decorated.namedChildren.filter((c) => c.type === 'decorator')) {
      const call = decorator.namedChildren[0];
      if (call?.type !== 'call') continue;
      const fn = call.childForFieldName('function');
      if (fn?.type !== 'attribute') continue;
      const owner = fn.childForFieldName('object')?.text ?? '';
      const attr = fn.childForFieldName('attribute')?.text ?? '';
      if (!HTTP.has(attr) || !ROUTE_OWNERS.test(lastSegment(owner))) continue;
      const args = call.childForFieldName('arguments')?.namedChildren ?? [];
      const route = stringValue(args[0]) ?? '/';
      const methods: string[] = [];
      if (attr === 'route' || attr === 'api_route') {
        const methodsArg = args.find(
          (a) => a.type === 'keyword_argument' && a.childForFieldName('name')?.text === 'methods',
        );
        for (const s of methodsArg?.childForFieldName('value')?.namedChildren ?? []) {
          const v = stringValue(s);
          if (v) methods.push(v.toUpperCase());
        }
        if (methods.length === 0) methods.push('GET');
      } else methods.push(attr.toUpperCase());
      const controls: ControlRef[] = [];
      for (const param of definition.childForFieldName('parameters')?.namedChildren ?? []) {
        const value =
          param.type === 'default_parameter' || param.type === 'typed_default_parameter'
            ? param.childForFieldName('value')
            : null;
        if (value?.type === 'call' && /Depends|Security/.test(value.childForFieldName('function')?.text ?? '')) {
          const dep = value.childForFieldName('arguments')?.namedChildren[0]?.text ?? 'Depends';
          controls.push({
            ref: dep,
            name: lastSegment(dep),
            kind: classifyControl(dep),
            source: 'dependency',
            path,
            line: line(param),
          });
        }
      }
      const dependsKw = args.find(
        (a) => a.type === 'keyword_argument' && a.childForFieldName('name')?.text === 'dependencies',
      );
      for (const item of dependsKw?.childForFieldName('value')?.namedChildren ?? []) {
        const dep =
          item.type === 'call' ? (item.childForFieldName('arguments')?.namedChildren[0]?.text ?? item.text) : item.text;
        controls.push({
          ref: dep,
          name: lastSegment(dep),
          kind: classifyControl(dep),
          source: 'dependency',
          path,
          line: line(item),
        });
      }
      // Other decorators on the same function (login_required, roles_required...) are controls too.
      for (const other of decorated.namedChildren.filter((c) => c.type === 'decorator' && c.id !== decorator.id)) {
        const text =
          other.namedChildren[0]?.type === 'call'
            ? (other.namedChildren[0].childForFieldName('function')?.text ?? other.text)
            : (other.namedChildren[0]?.text ?? '');
        if (text && classifyControl(text) !== 'OTHER')
          controls.push({
            ref: text,
            name: lastSegment(text),
            kind: classifyControl(text),
            source: 'decorator',
            path,
            line: line(other),
          });
      }
      for (const method of methods) {
        out.endpoints.push({
          id: endpointId(path, method, route, line(definition)),
          path,
          line: line(definition),
          method,
          route,
          framework: /fastapi|router/i.test(owner) || attr !== 'route' ? 'fastapi' : 'flask',
          handlers: symbol ? [symbol.key] : [],
          controls,
        });
      }
    }
  }
  return out;
}
