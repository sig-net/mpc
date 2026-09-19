/**
 * Report a long operation at ten-second intervals and stop reporting when it settles.
 *
 * @param label - The operation and its public correlation identifier.
 * @param operation - The asynchronous work.
 * @param deadline - Optional deadline for the displayed remaining time.
 * @returns The operation result.
 * @throws {Error} If the operation rejects.
 */
export async function withOperationProgress<T>(
  label: string,
  operation: () => Promise<T>,
  deadline?: number,
): Promise<T> {
  const started: number = Date.now();
  const status = (): string => {
    const elapsed: string = ((Date.now() - started) / 1000).toFixed(1);
    const remaining: string =
      deadline === undefined
        ? ""
        : `, ${Math.max(0, (deadline - Date.now()) / 1000).toFixed(1)}s remaining`;
    return `${elapsed}s elapsed${remaining}`;
  };
  console.log(`${label}: started`);
  const timer: ReturnType<typeof setInterval> = setInterval(() => {
    console.log(`${label}: ${status()}`);
  }, 10_000);
  try {
    const result: T = await operation();
    console.log(`${label}: completed (${status()})`);
    return result;
  } catch (error) {
    console.error(`${label}: failed (${status()})`);
    throw error;
  } finally {
    clearInterval(timer);
  }
}
