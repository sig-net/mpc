// One warning per distinct condition, for the flows' poll loops: a loop
// retrying every second would otherwise repeat the same message every tick.

const warnedKeys = new Set<string>();

/**
 * Log `message` the first time `key` is seen, and stay silent for every later
 * call with that key. Keys are process-wide, so a caller scopes its own by
 * including what makes the condition distinct (the flow and the request id).
 *
 * @param key - Identifies the condition: the first call carrying it warns, later ones stay quiet.
 * @param message - What to write to the console warning stream.
 */
export function warnOnce(key: string, message: string): void {
  if (warnedKeys.has(key)) {
    return;
  }
  warnedKeys.add(key);
  console.warn(message);
}
