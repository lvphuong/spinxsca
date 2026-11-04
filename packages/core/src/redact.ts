import { sha256Hex } from './ids';

/**
 * Minimal secret redaction applied to every code excerpt the engine stores or sends to an LLM.
 * Phase 1 replaces these patterns with the gitleaks rule set (ADR-023).
 */
const PATTERNS: Array<{ kind: string; regex: RegExp; replace?: (match: string, ...groups: string[]) => string }> = [
  { kind: 'private-key', regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { kind: 'aws-access-key', regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { kind: 'github-token', regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { kind: 'anthropic-key', regex: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { kind: 'slack-token', regex: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  {
    kind: 'credential',
    regex:
      /((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*)(["'])([^"'\s]{6,})\2/gi,
    replace: (_m, prefix, quote) => `${prefix}${quote}<REDACTED:credential>${quote}`,
  },
];

export function redactSecrets(text: string): { text: string; redactions: number } {
  let redactions = 0;
  let out = text;
  for (const pattern of PATTERNS) {
    out = out.replace(pattern.regex, (...args: string[]) => {
      redactions++;
      return pattern.replace ? pattern.replace(...(args as [string, ...string[]])) : `<REDACTED:${pattern.kind}>`;
    });
  }
  return { text: out, redactions };
}

export interface RedactionSpan {
  path: string;
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
}

/**
 * Masks known secret locations (for example from gitleaks) in a block of lines that starts at
 * `firstLine`. Single-line spans with columns mask only the secret; other spans mask whole lines.
 */
export function applyRedactions(
  lines: readonly string[],
  firstLine: number,
  path: string,
  spans: readonly RedactionSpan[],
): string[] {
  const relevant = spans.filter((s) => s.path === path);
  if (relevant.length === 0) return [...lines];
  return lines.map((line, index) => {
    const lineNo = firstLine + index;
    let out = line;
    for (const span of relevant) {
      if (lineNo < span.startLine || lineNo > span.endLine) continue;
      if (span.startLine === span.endLine && span.startColumn && span.endColumn && span.endColumn > span.startColumn) {
        out = `${out.slice(0, span.startColumn - 1)}<REDACTED:secret>${out.slice(span.endColumn - 1)}`;
      } else {
        out = `${out.match(/^\s*/)?.[0] ?? ''}<REDACTED:secret>`;
      }
    }
    return out;
  });
}

/**
 * Scrubs secrets from every text the autonomous review stores, logs or sends to a model (ADR-041):
 * values found by the secret scanners (held only in memory, never persisted) and the generic
 * patterns of `redactSecrets`. Known values become `<REDACTED:secret:hash8>` so equal secrets stay
 * correlatable without being revealed.
 */
export interface SecretScrubber {
  scrub(text: string): string;
  /** True when the text contains a known secret value or matches a secret pattern. */
  detects(text: string): boolean;
  /** Registers more secret values (for example from a history scan). */
  add(values: Iterable<string>): void;
  readonly size: number;
}

const MIN_SECRET_LENGTH = 6;

export function createSecretScrubber(
  options: { knownValues?: Iterable<string>; patterns?: boolean } = {},
): SecretScrubber {
  const known = new Map<string, string>();
  let ordered: string[] = [];
  const usePatterns = options.patterns ?? true;
  const add = (values: Iterable<string>) => {
    for (const raw of values) {
      const value = raw.trim();
      if (value.length < MIN_SECRET_LENGTH || known.has(value)) continue;
      known.set(value, `<REDACTED:secret:${sha256Hex(value).slice(0, 8)}>`);
    }
    // Longest first, so a secret containing another is replaced whole.
    ordered = [...known.keys()].sort((a, b) => b.length - a.length);
  };
  add(options.knownValues ?? []);
  return {
    scrub(text) {
      let out = text;
      for (const value of ordered) if (out.includes(value)) out = out.split(value).join(known.get(value) as string);
      return usePatterns ? redactSecrets(out).text : out;
    },
    detects(text) {
      if (ordered.some((value) => text.includes(value))) return true;
      return usePatterns && redactSecrets(text).redactions > 0;
    },
    add,
    get size() {
      return known.size;
    },
  };
}

/**
 * Builds the scrubber of a case from the secret locations found by the scanners: the exact value
 * at single-line column spans, otherwise quoted literals of eight or more characters on the flagged
 * lines. Values live only in memory.
 */
export async function scrubberFromSpans(
  readText: (path: string) => Promise<string | undefined>,
  spans: readonly RedactionSpan[],
): Promise<SecretScrubber> {
  const values: string[] = [];
  const cache = new Map<string, string[] | undefined>();
  for (const span of spans) {
    if (!cache.has(span.path)) cache.set(span.path, (await readText(span.path))?.split('\n'));
    const lines = cache.get(span.path);
    if (!lines) continue;
    for (let n = span.startLine; n <= span.endLine; n++) {
      const line = lines[n - 1];
      if (line === undefined) continue;
      if (span.startLine === span.endLine && span.startColumn && span.endColumn && span.endColumn > span.startColumn) {
        values.push(line.slice(span.startColumn - 1, span.endColumn - 1));
      } else {
        for (const m of line.matchAll(/(["'`])([^"'`\s]{8,})\1/g)) values.push(m[2] as string);
      }
    }
  }
  return createSecretScrubber({ knownValues: values });
}
