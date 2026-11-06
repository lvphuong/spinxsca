export class SpinxscaError extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message);
    this.name = 'SpinxscaError';
  }
}

export class CancelledError extends SpinxscaError {
  constructor(message = 'operation cancelled') {
    super(message, 'CANCELLED');
    this.name = 'CancelledError';
  }
}

/** What an operator asked a running job to do (ADR-052). */
export type RunControl = 'pause' | 'cancel';

/**
 * Abort reason of a job stopped by an operator. `pause` keeps the review case resumable (status
 * PAUSED, interrupted work stays in progress); `cancel` ends it. Any other abort counts as `cancel`.
 */
export class ControlRequestedError extends CancelledError {
  constructor(
    readonly action: RunControl,
    readonly by?: string,
  ) {
    super(`${action === 'pause' ? 'paused' : 'cancelled'}${by ? ` by ${by}` : ''}`);
    this.name = 'ControlRequestedError';
  }
}

/** The operator's request behind an aborted signal, or undefined while it still runs. */
export function controlOf(signal: AbortSignal | undefined): RunControl | undefined {
  if (!signal?.aborted) return undefined;
  const reason = signal.reason as { name?: string; action?: unknown } | undefined;
  return reason?.name === 'ControlRequestedError' && reason.action === 'pause' ? 'pause' : 'cancel';
}

export function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new CancelledError();
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
