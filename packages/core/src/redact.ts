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
