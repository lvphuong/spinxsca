/**
 * Lenient JSON recovery for model output (ADR-054). Small models wrap JSON in prose or fences,
 * leave trailing commas, use single quotes or Python literals, or get cut off mid-object. Each step
 * below is tried only when the previous text still does not parse; nothing here evaluates code.
 */
export interface RepairedJson {
  value: unknown;
  /** True when the input needed changes to parse (recorded for diagnostics). */
  repaired: boolean;
}

export function repairJson(text: string): RepairedJson | undefined {
  const direct = tryParse(text);
  if (direct !== FAIL) return { value: direct, repaired: false };
  let candidate = stripFences(text);
  const span = balancedSpan(candidate);
  if (span !== undefined) candidate = span;
  const steps: Array<(s: string) => string> = [
    (s) => s,
    removeTrailingCommas,
    convertSingleQuotes,
    quoteBareKeys,
    pythonLiterals,
    closeUnbalanced,
    (s) => removeTrailingCommas(closeUnbalanced(s)),
  ];
  let current = candidate;
  for (const step of steps) {
    current = step(current);
    const parsed = tryParse(current);
    if (parsed !== FAIL) return { value: parsed, repaired: true };
  }
  return undefined;
}

const FAIL = Symbol('fail');

function tryParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return FAIL;
  }
}

/** Content of the first fenced block when there is one; otherwise the text itself. */
export function stripFences(text: string): string {
  const fence = /```(?:json|JSON|javascript|js)?\s*\n?([\s\S]*?)```/.exec(text);
  if (fence?.[1]) return fence[1].trim();
  const open = /```(?:json|JSON)?\s*\n?([\s\S]*)$/.exec(text);
  return open?.[1] ? open[1].trim() : text.trim();
}

/**
 * The first balanced `{…}` or `[…]` span, ignoring brackets inside strings. An unterminated span is
 * returned to the end of the text so `closeUnbalanced` can finish it.
 */
export function balancedSpan(text: string): string | undefined {
  const start = text.search(/[{[]/);
  if (start < 0) return undefined;
  const stack: string[] = [];
  let inString: '"' | "'" | undefined;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i] as string;
    if (inString) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === inString) inString = undefined;
      continue;
    }
    if (c === '"' || c === "'") inString = c;
    else if (c === '{' || c === '[') stack.push(c);
    else if (c === '}' || c === ']') {
      stack.pop();
      if (stack.length === 0) return text.slice(start, i + 1);
    }
  }
  return text.slice(start);
}

/** Applies `fn` to every character outside string literals (strings pass through unchanged). */
function outsideStrings(text: string, fn: (chunk: string) => string): string {
  let out = '';
  let chunk = '';
  let inString: '"' | "'" | undefined;
  let escaped = false;
  for (const c of text) {
    if (inString) {
      out += c;
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === inString) inString = undefined;
      continue;
    }
    if (c === '"' || c === "'") {
      out += fn(chunk) + c;
      chunk = '';
      inString = c;
      continue;
    }
    chunk += c;
  }
  return out + fn(chunk);
}

export function removeTrailingCommas(text: string): string {
  // A comma followed only by whitespace and a closing bracket (string-aware: brackets in strings are skipped).
  let out = '';
  let inString: '"' | "'" | undefined;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    if (inString) {
      out += c;
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === inString) inString = undefined;
      continue;
    }
    if (c === '"' || c === "'") inString = c;
    if (c === ',') {
      const rest = text.slice(i + 1);
      const next = /^\s*([}\]])/.exec(rest);
      if (next) continue;
    }
    out += c;
  }
  return out;
}

/** `{'a': 'b'}` -> `{"a": "b"}` (apostrophes inside double-quoted strings are untouched). */
export function convertSingleQuotes(text: string): string {
  let out = '';
  let inDouble = false;
  let inSingle = false;
  let escaped = false;
  for (const c of text) {
    if (inDouble) {
      out += c;
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === '"') inDouble = false;
      continue;
    }
    if (inSingle) {
      if (escaped) {
        out += c === "'" ? "'" : `\\${c}`;
        escaped = false;
      } else if (c === '\\') escaped = true;
      else if (c === "'") {
        out += '"';
        inSingle = false;
      } else out += c === '"' ? '\\"' : c;
      continue;
    }
    if (c === '"') inDouble = true;
    else if (c === "'") {
      inSingle = true;
      out += '"';
      continue;
    }
    out += c;
  }
  return out;
}

export function quoteBareKeys(text: string): string {
  return outsideStrings(text, (chunk) => chunk.replace(/([{,]\s*)([A-Za-z_$][A-Za-z0-9_$]*)(\s*):/g, '$1"$2"$3:'));
}

export function pythonLiterals(text: string): string {
  return outsideStrings(text, (chunk) =>
    chunk
      .replace(/\bTrue\b/g, 'true')
      .replace(/\bFalse\b/g, 'false')
      .replace(/\bNone\b/g, 'null'),
  );
}

/** Closes an open string and every open bracket at the end of a truncated document. */
export function closeUnbalanced(text: string): string {
  const stack: string[] = [];
  let inString: '"' | "'" | undefined;
  let escaped = false;
  for (const c of text) {
    if (inString) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === inString) inString = undefined;
      continue;
    }
    if (c === '"' || c === "'") inString = c;
    else if (c === '{' || c === '[') stack.push(c === '{' ? '}' : ']');
    else if (c === '}' || c === ']') stack.pop();
  }
  let out = text.trimEnd();
  if (inString) out += inString;
  // A dangling `"key":` or `,` before the closers would still be invalid.
  out = out.replace(/[,:]\s*$/, '');
  return out + stack.reverse().join('');
}
