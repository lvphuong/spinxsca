import { execFile } from 'node:child_process';

export interface CliResult<T> {
  ok: boolean;
  exitCode: number;
  data?: T;
  error?: string;
}

/**
 * Runs the spinxsca CLI without a shell. Exit code 1 means "policy failed" and still carries JSON;
 * 2 is an error whose message is on stderr.
 */
export function runCli<T>(
  cliPath: string,
  args: readonly string[],
  cwd: string,
  options: { signal?: AbortSignal; env?: NodeJS.ProcessEnv } = {},
): Promise<CliResult<T>> {
  return new Promise((resolve) => {
    execFile(
      cliPath,
      [...args],
      {
        cwd,
        maxBuffer: 256 * 1024 * 1024,
        ...(options.signal ? { signal: options.signal } : {}),
        env: { ...process.env, NO_COLOR: '1', ...options.env },
      },
      (err, stdout, stderr) => {
        const exitCode =
          err && typeof (err as { code?: unknown }).code === 'number'
            ? ((err as { code: number }).code as number)
            : err
              ? -1
              : 0;
        if (err && exitCode !== 1 && exitCode !== 3) {
          const missing = (err as NodeJS.ErrnoException).code === 'ENOENT';
          resolve({
            ok: false,
            exitCode,
            error: missing
              ? `spinxsca CLI not found at "${cliPath}" (setting spinxsca.cliPath)`
              : lastLine(stderr) || err.message,
          });
          return;
        }
        try {
          resolve({ ok: true, exitCode, data: (stdout.trim() ? JSON.parse(stdout) : undefined) as T });
        } catch {
          resolve({ ok: false, exitCode, error: `unexpected CLI output: ${stdout.slice(0, 200)}` });
        }
      },
    );
  });
}

function lastLine(text: string): string {
  return (
    text
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('›'))
      .pop() ?? ''
  ).replace(/^error\s+/, '');
}
