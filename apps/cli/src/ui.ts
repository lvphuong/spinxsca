import { stripVTControlCharacters } from 'node:util';
import type { Logger } from '@spinxsca/core';
import type { Severity } from '@spinxsca/schemas';
import pc from 'picocolors';

/** Exit codes (docs/architecture/05 section 1). */
export const EXIT = { OK: 0, POLICY_FAILED: 1, ERROR: 2, PARTIAL_COVERAGE: 3 } as const;

export class CliError extends Error {
  constructor(
    message: string,
    readonly exitCode: number = EXIT.ERROR,
  ) {
    super(message);
    this.name = 'CliError';
  }
}

export function createLogger(verbose: boolean): Logger {
  const write = (level: string, color: (s: string) => string, message: string, fields?: Record<string, unknown>) => {
    const extra = fields && Object.keys(fields).length ? ` ${pc.dim(JSON.stringify(fields))}` : '';
    process.stderr.write(`${color(level)} ${message}${extra}\n`);
  };
  return {
    debug: (m, f) => verbose && write('debug', pc.dim, m, f),
    info: (m, f) => verbose && write('info ', pc.cyan, m, f),
    warn: (m, f) => write('warn ', pc.yellow, m, f),
    error: (m, f) => write('error', pc.red, m, f),
  };
}

export function status(message: string): void {
  process.stderr.write(`${pc.dim('›')} ${message}\n`);
}

export function severityLabel(severity: Severity): string {
  const colors: Record<Severity, (s: string) => string> = {
    CRITICAL: (s) => pc.bold(pc.red(s)),
    HIGH: pc.red,
    MEDIUM: pc.yellow,
    LOW: pc.blue,
    INFO: pc.dim,
  };
  return colors[severity](severity.padEnd(8));
}

/** Plain-text table; ANSI codes are ignored when computing widths. */
export function table(headers: string[], rows: string[][]): string {
  const visible = (s: string) => stripVTControlCharacters(s).length;
  const widths = headers.map((h, i) => Math.max(visible(h), ...rows.map((r) => visible(r[i] ?? ''))));
  const line = (cells: string[]) =>
    cells
      .map((c, i) => c + ' '.repeat(Math.max(0, (widths[i] ?? 0) - visible(c))))
      .join('  ')
      .trimEnd();
  return [pc.bold(line(headers)), ...rows.map(line)].join('\n');
}
