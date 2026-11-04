/**
 * Consecutive-failure circuit breaker, keyed per case. The reviewer trips after N consecutive denials
 * (then every ask goes to a human); the executor stops a run after N consecutive policy denials.
 */
export class ConsecutiveBreaker {
  private readonly counts: Map<string, number>;

  constructor(
    readonly threshold = 5,
    initial: Iterable<[string, number]> = [],
  ) {
    this.counts = new Map(initial);
  }

  count(key: string): number {
    return this.counts.get(key) ?? 0;
  }

  tripped(key: string): boolean {
    return this.count(key) >= this.threshold;
  }

  /** Records one outcome; returns whether this failure tripped the breaker. */
  record(key: string, failed: boolean): { count: number; tripped: boolean; justTripped: boolean } {
    const before = this.count(key);
    const count = failed ? before + 1 : 0;
    this.counts.set(key, count);
    return { count, tripped: count >= this.threshold, justTripped: before < this.threshold && count >= this.threshold };
  }

  reset(key: string): void {
    this.counts.delete(key);
  }
}
