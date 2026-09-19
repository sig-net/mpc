import { join } from "node:path";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import { levelPrivateStateProvider } from "@midnight-ntwrk/midnight-js-level-private-state-provider";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import {
  ZKConfigRegistry,
  type MidnightProvider,
  type MidnightProviders,
  type UnboundTransaction,
  type WalletProvider,
} from "@midnight-ntwrk/midnight-js/types";
import { httpClientProofProvider } from "@midnight-ntwrk/midnight-js-http-client-proof-provider";
import type { WalletFacade } from "@midnightntwrk/wallet-sdk-facade";
import {
  makeCompiledContract,
  signetContractManagedPath,
  type AccountKeys,
  type MidnightNodeConfig,
} from "@sig-net/midnight-contract-deploy";
import { Contract } from "./managed/erc20-vault/contract/index.js";
import { witnesses, type VaultPrivateState } from "./witnesses.js";

type VaultCircuitId = keyof InstanceType<typeof Contract>["provableCircuits"] & string;
type VaultPrivateStateId = "rust-real-stack-vault";
export const VAULT_PRIVATE_STATE_ID: VaultPrivateStateId = "rust-real-stack-vault";
type VaultProviders = MidnightProviders<VaultCircuitId, VaultPrivateStateId, VaultPrivateState>;

export const vaultManagedPath = join(import.meta.dirname, "managed", "erc20-vault");

export const vaultCompiledContract = makeCompiledContract<
  Contract<VaultPrivateState>,
  VaultPrivateState
>("rust-real-stack-vault", Contract, witnesses, vaultManagedPath);

function walletProvider(
  facade: WalletFacade,
  keys: AccountKeys,
): WalletProvider & MidnightProvider {
  return {
    getCoinPublicKey: () => keys.shieldedSecretKeys.coinPublicKey,
    getEncryptionPublicKey: () => keys.shieldedSecretKeys.encryptionPublicKey,
    async balanceTx(tx: UnboundTransaction, ttl?: Date) {
      const recipe = await facade.balanceUnboundTransaction(
        tx as never,
        { shieldedSecretKeys: keys.shieldedSecretKeys, dustSecretKey: keys.dustSecretKey },
        { ttl: ttl ?? new Date(Date.now() + 30 * 60 * 1000) },
      );
      const signed = await facade.signRecipe(recipe, keys.unshieldedKeystore.signDataAsync);
      return (await facade.finalizeRecipe(signed)) as never;
    },
    submitTx: (tx) => facade.submitTransaction(tx as never) as never,
  };
}

export function buildProviders(
  facade: WalletFacade,
  keys: AccountKeys,
  config: MidnightNodeConfig,
  databasePath: string,
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
    // Vault requests call the Signet singleton and need both verifier-key bundles.
    proofProvider: httpClientProofProvider({
      url: config.proofServerUrl,
      zkConfigProvider: new ZKConfigRegistry([vaultZk, signetZk]),
      timeout: 900_000,
    }),
    walletProvider: wallet,
    midnightProvider: wallet,
  };
}
