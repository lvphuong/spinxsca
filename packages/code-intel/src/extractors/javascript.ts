import type { ControlRef, FileExtraction, GlobalControl, Language, SymbolRecord } from '../types';
import {
  classifyControl,
  emptyExtraction,
  endpointId,
  isControlName,
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

const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'all']);
const ROUTE_OWNERS = /^(app|router|server|api|routes?|fastify|koa|express|r|v\d+)$/i;
const FUNCTION_NODES = new Set(['arrow_function', 'function_expression', 'function', 'generator_function']);
const NEST_HTTP = new Set(['Get', 'Post', 'Put', 'Patch', 'Delete', 'Head', 'Options', 'All']);
const DECLARATION_TYPES = new Set([
  'function_declaration',
  'generator_function_declaration',
  'class_declaration',
  'abstract_class_declaration',
  'method_definition',
  'lexical_declaration',
  'variable_declaration',
]);

interface Scope {
  qualified: string;
  key: string;
}

/** JavaScript / TypeScript extraction: symbols, imports, calls, Express/Fastify/Koa routes, NestJS controllers. */
export function extractJavaScript(path: string, language: Language, root: SyntaxNode): FileExtraction {
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
  const anonymousCounter = new Map<number, number>();
  const symbolByNode = new Map<number, SymbolRecord>();
  const exportedNames = new Set<string>();

  // Pass 1: declarations (functions, classes, methods, arrow bindings).
  const declare = (node: SyntaxNode, scope: Scope, exported: boolean): void => {
    switch (node.type) {
      case 'function_declaration':
      case 'generator_function_declaration': {
        const name = node.childForFieldName('name')?.text;
        if (!name) return;
        const qualified = scope.qualified ? `${scope.qualified}.${name}` : name;
        const symbol = makeSymbol({ path, language, name, qualifiedName: qualified, kind: 'function', node, exported });
        out.symbols.push(symbol);
        symbolByNode.set(node.id, symbol);
        declareChildren(node.childForFieldName('body'), { qualified, key: symbol.key }, false);
        return;
      }
      case 'class_declaration':
      case 'abstract_class_declaration': {
        const name = node.childForFieldName('name')?.text;
        if (!name) return;
        const qualified = scope.qualified ? `${scope.qualified}.${name}` : name;
        const symbol = makeSymbol({ path, language, name, qualifiedName: qualified, kind: 'class', node, exported });
        out.symbols.push(symbol);
        symbolByNode.set(node.id, symbol);
        const body = node.childForFieldName('body');
        for (const member of body?.namedChildren ?? []) {
          if (member.type === 'public_field_definition') {
            const field = member.childForFieldName('name')?.text;
            const type = member.childForFieldName('type')?.namedChildren[0]?.text;
            if (field && type) pushFieldType(out, { owner: symbol.key, field, type });
          }
          if (member.type === 'method_definition' && member.childForFieldName('name')?.text === 'constructor') {
            for (const param of member.childForFieldName('parameters')?.namedChildren ?? []) {
              const hasModifier =
                param.namedChildren.some(
                  (c) => c.type === 'accessibility_modifier' || c.type === 'override_modifier',
                ) || /\b(private|public|protected|readonly)\b/.test(param.text.split(':')[0] ?? '');
              const field =
                param.childForFieldName('pattern')?.text ??
                param.namedChildren.find((c) => c.type === 'identifier')?.text;
              const type = param.childForFieldName('type')?.namedChildren[0]?.text;
              if (hasModifier && field && type) pushFieldType(out, { owner: symbol.key, field, type });
            }
          }
          if (member.type === 'method_definition') {
            const methodName = member.childForFieldName('name')?.text ?? 'anonymous';
            const method = makeSymbol({
              path,
              language,
              name: methodName,
              qualifiedName: `${qualified}.${methodName}`,
              kind: 'method',
              node: member,
              owner: symbol.key,
              exported,
            });
            out.symbols.push(method);
            symbolByNode.set(member.id, method);
            declareChildren(
              member.childForFieldName('body'),
              { qualified: method.qualifiedName, key: method.key },
              false,
            );
          }
        }
        return;
      }
      case 'lexical_declaration':
      case 'variable_declaration': {
        for (const declarator of node.namedChildren.filter((c) => c.type === 'variable_declarator')) {
          const nameNode = declarator.childForFieldName('name');
          const value = declarator.childForFieldName('value');
          if (!nameNode || !value || nameNode.type !== 'identifier') continue;
          if (FUNCTION_NODES.has(value.type)) {
            const name = nameNode.text;
            const qualified = scope.qualified ? `${scope.qualified}.${name}` : name;
            const symbol = makeSymbol({
              path,
              language,
              name,
              qualifiedName: qualified,
              kind: 'function',
              node: declarator,
              exported,
            });
            out.symbols.push(symbol);
            symbolByNode.set(value.id, symbol);
            declareChildren(value.childForFieldName('body'), { qualified, key: symbol.key }, false);
          }
        }
        return;
      }
      default:
        return;
    }
  };
  const declareChildren = (node: SyntaxNode | null, scope: Scope, _exported: boolean): void => {
    if (!node) return;
    walk(node, (n) => {
      if (n.id === node.id) return true;
      if (n.type === 'export_statement') {
        const decl = n.childForFieldName('declaration') ?? n.namedChildren.find((c) => DECLARATION_TYPES.has(c.type));
        if (decl) {
          declare(decl, scope, true);
          return false;
        }
        for (const spec of n.descendantsOfType('export_specifier'))
          exportedNames.add(spec.childForFieldName('name')?.text ?? '');
        return false;
      }
      if (DECLARATION_TYPES.has(n.type)) {
        declare(n, scope, false);
        return false;
      }
      // Do not descend into nested function bodies here; declare() handles them with the right scope.
      return !FUNCTION_NODES.has(n.type);
    });
  };
  declareChildren(root, { qualified: '', key: moduleKey }, false);
  for (const symbol of out.symbols) if (exportedNames.has(symbol.name)) symbol.exported = true;

  // Enclosing symbol lookup by position.
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

  // Imports.
  walk(root, (n) => {
    if (n.type === 'import_statement') {
      const specifier = stringValue(n.childForFieldName('source'));
      if (!specifier) return false;
      const names: Array<{ imported: string; local: string }> = [];
      const clause = n.namedChildren.find((c) => c.type === 'import_clause');
      for (const c of clause?.namedChildren ?? []) {
        if (c.type === 'identifier') names.push({ imported: 'default', local: c.text });
        else if (c.type === 'namespace_import') names.push({ imported: '*', local: c.namedChildren[0]?.text ?? '*' });
        else if (c.type === 'named_imports') {
          for (const spec of c.namedChildren.filter((s) => s.type === 'import_specifier')) {
            const imported = spec.childForFieldName('name')?.text ?? '';
            const local = spec.childForFieldName('alias')?.text ?? imported;
            names.push({ imported, local });
          }
        }
      }
      out.imports.push({ path, specifier, names, line: line(n) });
      return false;
    }
    if (n.type === 'variable_declarator') {
      const value = n.childForFieldName('value');
      const nameNode = n.childForFieldName('name');
      const call =
        value?.type === 'call_expression'
          ? value
          : value?.type === 'member_expression'
            ? value.childForFieldName('object')
            : null;
      if (call?.type === 'call_expression' && call.childForFieldName('function')?.text === 'require' && nameNode) {
        const specifier = stringValue(call.childForFieldName('arguments')?.namedChildren[0]);
        if (!specifier) return true;
        const names: Array<{ imported: string; local: string }> = [];
        if (nameNode.type === 'identifier') names.push({ imported: 'default', local: nameNode.text });
        else if (nameNode.type === 'object_pattern') {
          for (const p of nameNode.namedChildren) {
            if (p.type === 'shorthand_property_identifier_pattern') names.push({ imported: p.text, local: p.text });
            else if (p.type === 'pair_pattern') {
              const key = p.childForFieldName('key')?.text ?? '';
              names.push({ imported: key, local: p.childForFieldName('value')?.text ?? key });
            }
          }
        }
        out.imports.push({ path, specifier, names, line: line(n) });
      }
    }
    return true;
  });

  // Calls, routes, middleware and mounts.
  const handlerKey = (arg: SyntaxNode, method: string, route: string): string | undefined => {
    if (FUNCTION_NODES.has(arg.type)) {
      const existing = symbolByNode.get(arg.id);
      if (existing) return existing.key;
      const n = (anonymousCounter.get(line(arg)) ?? 0) + 1;
      anonymousCounter.set(line(arg), n);
      const qualified = `<${method.toUpperCase()} ${route}>${n > 1 ? `#${n}` : ''}`;
      const symbol = makeSymbol({
        path,
        language,
        name: qualified,
        qualifiedName: qualified,
        kind: 'handler',
        node: arg,
        exported: false,
      });
      out.symbols.push(symbol);
      ordered.push(symbol);
      ordered.sort((a, b) => a.startLine - b.startLine || b.endLine - a.endLine);
      symbolByNode.set(arg.id, symbol);
      return symbol.key;
    }
    if (arg.type === 'identifier' || arg.type === 'member_expression') return arg.text;
    if (arg.type === 'call_expression') return arg.childForFieldName('function')?.text ?? arg.text;
    if (arg.type === 'array') return undefined;
    return undefined;
  };
  const controlFrom = (ref: string, source: ControlRef['source'], lineNo: number): ControlRef => ({
    ref,
    name: lastSegment(ref),
    kind: classifyControl(ref),
    source,
    path,
    line: lineNo,
  });

  walk(root, (n) => {
    if (n.type !== 'call_expression') return true;
    const fn = n.childForFieldName('function');
    const args = n.childForFieldName('arguments')?.namedChildren ?? [];
    if (!fn) return true;
    const callee = fn.text.replace(/\s+/g, '');
    out.calls.push({ path, line: line(n), callerKey: enclosing(line(n)).key, callee, name: lastSegment(callee) });

    if (fn.type === 'member_expression') {
      const owner = fn.childForFieldName('object')?.text ?? '';
      const prop = fn.childForFieldName('property')?.text ?? '';
      const ownerName = lastSegment(owner);
      const firstRoute = stringValue(args[0]);
      if (HTTP_METHODS.has(prop) && ROUTE_OWNERS.test(ownerName) && firstRoute !== undefined) {
        const method = prop.toUpperCase();
        const handlers: string[] = [];
        const controls: ControlRef[] = [];
        const handlerArgs = args.slice(1).flatMap((a) => (a.type === 'array' ? a.namedChildren : [a]));
        for (const [i, arg] of handlerArgs.entries()) {
          if (arg.type === 'object') {
            // fastify route options: { preHandler: auth } / { preValidation: [...] }
            for (const pair of arg.namedChildren.filter((c) => c.type === 'pair')) {
              const key = pair.childForFieldName('key')?.text ?? '';
              if (/^(preHandler|preValidation|onRequest|preSerialization)$/.test(key)) {
                const value = pair.childForFieldName('value');
                const items = value?.type === 'array' ? value.namedChildren : value ? [value] : [];
                for (const item of items) controls.push(controlFrom(item.text, 'inline', line(item)));
              }
            }
            continue;
          }
          const key = handlerKey(arg, prop, firstRoute);
          if (!key) continue;
          handlers.push(key);
          if (i < handlerArgs.length - 1 && !FUNCTION_NODES.has(arg.type))
            controls.push(controlFrom(key, 'inline', line(arg)));
        }
        out.endpoints.push({
          id: endpointId(path, method, firstRoute, line(n)),
          path,
          line: line(n),
          method,
          route: firstRoute,
          framework: /fastify/i.test(ownerName) ? 'fastify' : 'express',
          handlers,
          controls,
        });
      } else if (prop === 'use' && ROUTE_OWNERS.test(ownerName) && args.length > 0) {
        const mountPath = firstRoute;
        const targets = (mountPath === undefined ? args : args.slice(1)).flatMap((a) =>
          a.type === 'array' ? a.namedChildren : [a],
        );
        for (const target of targets) {
          const text = FUNCTION_NODES.has(target.type)
            ? ''
            : target.type === 'call_expression'
              ? (target.childForFieldName('function')?.text ?? '')
              : target.text;
          if (!text) continue;
          const head = text.split('.')[0] ?? text;
          const importedModule = out.imports.some((i) => i.names.some((n) => n.local === head) && !isControlName(text));
          if (
            mountPath !== undefined &&
            (importedModule || (/router|routes|controller|api/i.test(text) && !isControlName(text)))
          ) {
            out.mounts.push({ line: line(target), prefix: mountPath, target: text });
            continue;
          }
          const control: GlobalControl = {
            path,
            line: line(target),
            owner: ownerName,
            ...(mountPath !== undefined ? { mountPath } : {}),
            ref: text,
            name: lastSegment(text),
            kind: classifyControl(text),
          };
          out.globalControls.push(control);
        }
      }
    }
    return true;
  });

  extractNest(path, root, out, symbolByNode, controlFrom);
  return out;
}

/** NestJS: @Controller('prefix') classes with @Get/@Post methods; @UseGuards on class or method. */
function extractNest(
  path: string,
  root: SyntaxNode,
  out: FileExtraction,
  symbolByNode: Map<number, SymbolRecord>,
  controlFrom: (ref: string, source: ControlRef['source'], lineNo: number) => ControlRef,
): void {
  const decoratorsOf = (node: SyntaxNode): SyntaxNode[] => {
    const found: SyntaxNode[] = [];
    // Decorators are siblings preceding the node (export_statement children or class_body members).
    let sibling = node.previousNamedSibling;
    while (sibling && sibling.type === 'decorator') {
      found.unshift(sibling);
      sibling = sibling.previousNamedSibling;
    }
    for (const child of node.namedChildren) if (child.type === 'decorator') found.push(child);
    return found;
  };
  const decoratorInfo = (d: SyntaxNode): { name: string; args: SyntaxNode[] } => {
    const inner = d.namedChildren[0];
    if (inner?.type === 'call_expression') {
      return {
        name: inner.childForFieldName('function')?.text ?? '',
        args: inner.childForFieldName('arguments')?.namedChildren ?? [],
      };
    }
    return { name: inner?.text ?? '', args: [] };
  };
  for (const cls of root.descendantsOfType(['class_declaration', 'abstract_class_declaration'])) {
    const classDecorators = decoratorsOf(cls).map(decoratorInfo);
    const controller = classDecorators.find((d) => d.name === 'Controller');
    if (!controller) continue;
    const prefix = stringValue(controller.args[0]) ?? '';
    const classControls = classDecorators
      .filter((d) => /^(UseGuards|UseInterceptors|UsePipes|Roles|Auth|Public)$/.test(d.name))
      .flatMap((d) =>
        d.args.length
          ? d.args.map((a) => controlFrom(a.text, 'decorator', line(a)))
          : [controlFrom(d.name, 'decorator', line(cls))],
      );
    for (const member of cls.childForFieldName('body')?.namedChildren ?? []) {
      if (member.type !== 'method_definition') continue;
      const decorators = decoratorsOf(member).map(decoratorInfo);
      const http = decorators.find((d) => NEST_HTTP.has(d.name));
      if (!http) continue;
      const route = joinRoute(`/${prefix}`, stringValue(http.args[0]) ?? '');
      const method = http.name.toUpperCase();
      const symbol = symbolByNode.get(member.id);
      const methodControls = decorators
        .filter((d) => /^(UseGuards|UseInterceptors|UsePipes|Roles|Auth|Public)$/.test(d.name))
        .flatMap((d) =>
          d.args.length
            ? d.args.map((a) => controlFrom(a.text, 'decorator', line(a)))
            : [controlFrom(d.name, 'decorator', line(member))],
        );
      out.endpoints.push({
        id: endpointId(path, method, route, line(member)),
        path,
        line: line(member),
        method,
        route,
        framework: 'nestjs',
        handlers: symbol ? [symbol.key] : [],
        controls: [...classControls, ...methodControls],
      });
    }
  }
}
