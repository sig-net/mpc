// `Promise.race` handles the loser, so the abandoned attempt's own late failure surfaces nowhere.
export async function withDeadline<T>(
  work: Promise<T>,
  ms: number,
  timeoutError: Error,
  onTimeout?: () => void,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          reject(timeoutError);
          onTimeout?.();
        }, ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
