import { fileURLToPath } from "node:url";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import { levelPrivateStateProvider } from "@midnight-ntwrk/midnight-js-level-private-state-provider";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import { ZKConfigRegistry, type MidnightProviders } from "@midnight-ntwrk/midnight-js/types";
import { httpClientProofProvider } from "@midnight-ntwrk/midnight-js-http-client-proof-provider";
import type { WalletFacade } from "@midnightntwrk/wallet-sdk-facade";
import {
  makeCompiledContract,
  signetContractManagedPath,
  type AccountKeys,
  type MidnightNodeConfig,
} from "@sig-net/midnight-contract-deploy";
import { Contract, type Witnesses } from "./managed/erc20-vault/contract/index.js";
import { recordingProofProvider, type CallPlacement } from "./placement.js";
import { walletProvider } from "./providers.js";

export interface VaultPrivateState {
  readonly secretKey: Uint8Array;
}

// The vault's identity commitment, its derivation path for deposits, is recomputed from
// this witness in every gated circuit.
const vaultWitnesses: Witnesses<VaultPrivateState> = {
  callerSecretKey: ({ privateState }): [VaultPrivateState, Uint8Array] => [
    privateState,
    privateState.secretKey,
  ],
};

export type VaultContract = Contract<VaultPrivateState>;
type VaultCircuitId = keyof VaultContract["provableCircuits"] & string;
type VaultPrivateStateId = "rust-real-stack-vault";
export const VAULT_PRIVATE_STATE_ID: VaultPrivateStateId = "rust-real-stack-vault";
export type VaultProviders = MidnightProviders<
  VaultCircuitId,
  VaultPrivateStateId,
  VaultPrivateState
>;

export const vaultManagedPath = fileURLToPath(new URL("./managed/erc20-vault", import.meta.url));

export const vaultCompiledContract = makeCompiledContract<VaultContract, VaultPrivateState>(
  "rust-real-stack-vault",
  Contract,
  vaultWitnesses,
  vaultManagedPath,
);

export function buildVaultProviders(
  facade: WalletFacade,
  keys: AccountKeys,
  config: MidnightNodeConfig,
  databasePath: string,
  onPlacement: (placement: CallPlacement[]) => void,
): VaultProviders {
  const vaultZk = new NodeZkConfigProvider<VaultCircuitId>(vaultManagedPath);
  const signetZk = new NodeZkConfigProvider<string>(signetContractManagedPath);
  const wallet = walletProvider(facade, keys);
  return {
    privateStateProvider: levelPrivateStateProvider({
      midnightDbName: databasePath,
      privateStateStoreName: "vault-private-state",
      signingKeyStoreName: "vault-signing-keys",
      accountId: wallet.getCoinPublicKey(),
      privateStoragePasswordProvider: () => "MpcRealStack#2026!",
    }),
    publicDataProvider: indexerPublicDataProvider({
      queryURL: config.indexerUrl,
      subscriptionURL: config.indexerWsUrl,
    }),
    zkConfigProvider: vaultZk,
    // The send circuits call the Signet singleton; the registry binds each call to its
    // contract's key bundle. The settlement circuits' ECDSA proofs take minutes.
    proofProvider: recordingProofProvider(
      httpClientProofProvider({
        url: config.proofServerUrl,
        zkConfigProvider: new ZKConfigRegistry([vaultZk, signetZk]),
        timeout: 900_000,
      }),
      onPlacement,
    ),
    walletProvider: wallet,
    midnightProvider: wallet,
  };
}
