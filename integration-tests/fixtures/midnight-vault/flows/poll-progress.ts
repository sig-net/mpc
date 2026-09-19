/** State and rate-limited reporting for one request's polling lifetime. */
export class PollProgress {
  private readonly started: number = Date.now();
  private nextReport = 0;
  private status = "no response observed";
  private lastFailure: string | undefined;
  private readonly warnings = new Set<string>();

  /**
   * @param label - Poll kind and request ID.
   * @param timeoutMs - Poll deadline relative to construction.
   */
  constructor(
    private readonly label: string,
    private readonly timeoutMs: number,
  ) {}

  /**
   * Record current progress and report at most once per ten seconds.
   *
   * @param status - Current observation and verification counts.
   */
  update(status: string): void {
    this.status = status;
    if (Date.now() < this.nextReport) return;
    this.nextReport = Date.now() + 10_000;
    console.log(this.summary());
  }

  /**
   * Retain the last failure and report each distinct condition once per poll.
   *
   * @param key - Stable condition identifier.
   * @param message - Failure details without private key material.
   */
  failure(key: string, message: string): void {
    this.lastFailure = message;
    if (this.warnings.has(key)) return;
    this.warnings.add(key);
    console.warn(`${this.label}: ${message}`);
  }

  /**
   * Describe the latest state, elapsed time and last failure.
   *
   * @returns The diagnostic line used for progress and timeout errors.
   */
  summary(): string {
    const elapsed: number = Date.now() - this.started;
    return `${this.label}: ${this.status}, ${(elapsed / 1000).toFixed(1)}s elapsed, ${(Math.max(0, this.timeoutMs - elapsed) / 1000).toFixed(1)}s remaining${this.lastFailure === undefined ? "" : `. Last failure: ${this.lastFailure}`}`;
  }
}
