import type { Witnesses } from "./managed/caller/contract/index.js";

export interface CallerPrivateState {
  readonly secretKey: Uint8Array;
}

export const createCallerPrivateState = (secretKey: Uint8Array): CallerPrivateState => ({
  secretKey,
});

export const witnesses: Witnesses<CallerPrivateState> = {
  deployerSecretKey: ({ privateState }) => [privateState, privateState.secretKey],
};
