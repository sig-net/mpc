import type { Witnesses } from "./managed/erc20-vault/contract/index.js";

export interface VaultPrivateState {
  readonly secretKey: Uint8Array;
}

export const createPrivateState = (secretKey: Uint8Array): VaultPrivateState => ({ secretKey });

export const witnesses: Witnesses<VaultPrivateState> = {
  callerSecretKey: ({ privateState }): [VaultPrivateState, Uint8Array] => [
    privateState,
    privateState.secretKey,
  ],
};
