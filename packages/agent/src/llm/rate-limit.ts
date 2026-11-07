import { estimateRequestTokens } from '../runtime/compaction';
import type { CompletionRequest, CompletionResult, LlmProvider } from './types';

/** Per-endpoint limits shared by every role that talks to it (ADR-055). */
export interface RateLimit {
  /** Requests per minute. */
  rpm?: number;
  /** Input tokens per minute (estimated). */
  tpm?: number;
  /** Requests in flight. */
  concurrency?: number;
}

/** Defaults when the operator sets none: generous for the Claude API, serial for a single local GPU. */
export function defaultRateLimit(providerId: string): RateLimit {
  switch (providerId) {
    case 'anthropic':
      return { rpm: 50, tpm: 400_000, concurrency: 6 };
    case 'openai-compatible':
      return { concurrency: 2 };
    case 'ollama':
      return { concurrency: 1 };
    default:
      return {};
  }
}

/**
 * Token bucket per minute for requests and tokens plus a concurrency gate. `acquire` resolves with a
 * release function; a `penalize` call (after a 429) holds every caller back for a while.
 */
export class RateLimiter {
  private readonly requests: number[] = [];
  private readonly tokens: Array<{ at: number; n: number }> = [];
  private active = 0;
  private readonly waiting: Array<() => void> = [];
  private blockedUntil = 0;

  constructor(
    readonly limit: RateLimit,
    private readonly now: () => number = () => Date.now(),
    private readonly sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
  ) {}

  async acquire(estimatedTokens: number, signal?: AbortSignal): Promise<() => void> {
    const concurrency = this.limit.concurrency ?? Number.POSITIVE_INFINITY;
    while (this.active >= concurrency) {
      if (signal?.aborted) throw new Error('cancelled while waiting for a rate-limit slot');
      await new Promise<void>((resolve) => this.waiting.push(resolve));
    }
    this.active++;
    try {
      for (;;) {
        const wait = this.waitMs(estimatedTokens);
        if (wait <= 0) break;
        if (signal?.aborted) throw new Error('cancelled while waiting for a rate-limit slot');
        await this.sleep(Math.min(wait, 5_000));
      }
    } catch (err) {
      this.release();
      throw err;
    }
    const t = this.now();
    this.requests.push(t);
    this.tokens.push({ at: t, n: estimatedTokens });
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.release();
    };
  }

  /** Blocks new requests for `ms` (after a 429 or an explicit Retry-After). */
  penalize(ms: number): void {
    this.blockedUntil = Math.max(this.blockedUntil, this.now() + ms);
  }

  private release(): void {
    this.active--;
    this.waiting.shift()?.();
  }

  private waitMs(estimatedTokens: number): number {
    const t = this.now();
    let wait = Math.max(0, this.blockedUntil - t);
    const minute = t - 60_000;
    while (this.requests.length && (this.requests[0] as number) <= minute) this.requests.shift();
    while (this.tokens.length && (this.tokens[0] as { at: number }).at <= minute) this.tokens.shift();
    if (this.limit.rpm && this.requests.length >= this.limit.rpm)
      wait = Math.max(wait, (this.requests[0] as number) + 60_000 - t);
    if (this.limit.tpm) {
      let used = this.tokens.reduce((n, e) => n + e.n, 0);
      let i = 0;
      while (used + estimatedTokens > this.limit.tpm && i < this.tokens.length) {
        const entry = this.tokens[i] as { at: number; n: number };
        wait = Math.max(wait, entry.at + 60_000 - t);
        used -= entry.n;
        i++;
      }
    }
    return wait;
  }
}

/** Wraps a provider so every request passes the limiter; 429s penalize the shared limiter. */
export function withRateLimit(inner: LlmProvider, limiter: RateLimiter): LlmProvider {
  return {
    id: inner.id,
    model: inner.model,
    capabilities: () => inner.capabilities(),
    ...(inner.countTokens ? { countTokens: inner.countTokens.bind(inner) } : {}),
    async complete(request: CompletionRequest, options): Promise<CompletionResult> {
      const estimate = estimateRequestTokens(request.system, request.tools, request.messages);
      const release = await limiter.acquire(estimate, options?.signal);
      try {
        return await inner.complete(request, options);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (/\b429\b|rate limit|too many requests/i.test(message)) {
          const retryAfter = /retry[- ]after[":\s]+(\d+)/i.exec(message);
          limiter.penalize(retryAfter ? Number(retryAfter[1]) * 1000 : 2_000);
        }
        throw err;
      } finally {
        release();
      }
    },
  };
}
