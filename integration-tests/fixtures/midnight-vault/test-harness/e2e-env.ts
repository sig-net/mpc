// Env-accumulator assertions shared by the setup pipeline and the flow test
// files. The accumulator itself is lib's `buildBaseEnv`, which every deploy
// entrypoint starts from too. This module MUST stay free of `vitest` imports:
// it is loaded by globalSetup in vitest's main process, where the worker-only
// test APIs are unavailable. The worker-side half (inject + hooks) lives in
// flow-hooks.ts.

/**
 * Assert a prior setup step populated `name`, failing with a pointed message.
 *
 * @param env - The suite's env accumulator.
 * @param name - The env-var name a prior step (or the operator's `.env`) must have set.
 * @returns The non-empty value.
 * @throws {Error} If the variable is unset or empty.
 */
export function requireEnv(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value) {
    throw new Error(
      `${name} is not set — did the step that derives it run (or is it missing from your .env)?`,
    );
  }
  return value;
}
