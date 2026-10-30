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

export function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new CancelledError();
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
