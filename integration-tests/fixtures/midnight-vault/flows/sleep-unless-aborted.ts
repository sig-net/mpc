/**
 * Resolve after `ms`, or immediately once `signal` aborts. Spaces out the
 * flows' polling loops.
 *
 * @param ms - Milliseconds to wait.
 * @param signal - Abort to resolve early.
 * @returns A promise that settles after the delay or the abort.
 */
export function sleepUnlessAborted(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      resolve();
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
