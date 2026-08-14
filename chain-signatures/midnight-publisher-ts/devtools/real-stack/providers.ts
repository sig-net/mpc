import { fileURLToPath } from "node:url";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import { levelPrivateStateProvider } from "@midnight-ntwrk/midnight-js-level-private-state-provider";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import {
  createProofProvider,
  ZKConfigRegistry,
  zkConfigToProvingKeyMaterial,
  type MidnightProvider,
  type MidnightProviders,
  type ProofProvider,
  type UnboundTransaction,
  type WalletProvider,
  type ZKConfigProvider,
} from "@midnight-ntwrk/midnight-js/types";
import { httpClientProvingProvider } from "@midnight-ntwrk/midnight-js-http-client-proof-provider";
import type { ProvingKeyMaterial, ProvingProvider } from "@midnightntwrk/ledger-v9";
import type { WalletFacade } from "@midnightntwrk/wallet-sdk-facade";
import {
  makeCompiledContract,
  signetContractManagedPath,
  type AccountKeys,
  type MidnightNodeConfig,
} from "@sig-net/midnight-contract-deploy";
import { Contract } from "./managed/caller/contract/index.js";
import { witnesses, type CallerPrivateState } from "./witnesses.js";

type CallerCircuitId = keyof InstanceType<typeof Contract>["provableCircuits"] & string;
type CallerPrivateStateId = "rust-real-stack-caller";
export const CALLER_PRIVATE_STATE_ID: CallerPrivateStateId = "rust-real-stack-caller";
type CallerProviders = MidnightProviders<CallerCircuitId, CallerPrivateStateId, CallerPrivateState>;

const callerManagedPath = fileURLToPath(new URL("./managed/caller", import.meta.url));

export const callerCompiledContract = makeCompiledContract<
  Contract<CallerPrivateState>,
  CallerPrivateState
>("rust-real-stack-caller", Contract, witnesses, callerManagedPath);

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

function crossContractProofProvider(
  proofServerUrl: string,
  providers: readonly ZKConfigProvider<string>[],
): ProofProvider {
  const registry = new ZKConfigRegistry([...providers]);
  const base = httpClientProvingProvider(
    proofServerUrl,
    registry as unknown as ZKConfigProvider<string>,
  );
  const lookupKey = async (keyLocation: string): Promise<ProvingKeyMaterial | undefined> => {
    const resolved = await registry.resolveKeyLocation(keyLocation);
    if (resolved !== undefined) return zkConfigToProvingKeyMaterial(resolved);
    for (const provider of providers) {
      try {
        return zkConfigToProvingKeyMaterial(await provider.get(keyLocation));
      } catch {
        // The key may belong to the next contract in the call tree.
      }
    }
    return undefined;
  };
  const provingProvider: ProvingProvider = { ...base, lookupKey };
  return createProofProvider(provingProvider);
}

export function buildCallerProviders(
  facade: WalletFacade,
  keys: AccountKeys,
  config: MidnightNodeConfig,
  databasePath: string,
): CallerProviders {
  const callerZk = new NodeZkConfigProvider<CallerCircuitId>(callerManagedPath);
  const signetZk = new NodeZkConfigProvider<string>(signetContractManagedPath);
  const wallet = walletProvider(facade, keys);
  return {
    privateStateProvider: levelPrivateStateProvider({
      midnightDbName: databasePath,
      privateStateStoreName: "caller-private-state",
      signingKeyStoreName: "caller-signing-keys",
      accountId: wallet.getCoinPublicKey(),
      privateStoragePasswordProvider: () => "MpcRealStack#2026!",
    }),
    publicDataProvider: indexerPublicDataProvider({
      queryURL: config.indexerUrl,
      subscriptionURL: config.indexerWsUrl,
    }),
    zkConfigProvider: callerZk,
    proofProvider: crossContractProofProvider(config.proofServerUrl, [callerZk, signetZk]),
    walletProvider: wallet,
    midnightProvider: wallet,
  };
}
