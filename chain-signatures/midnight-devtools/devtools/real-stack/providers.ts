import { fileURLToPath } from "node:url";
import type { ContractModuleProvider } from "@midnight-ntwrk/compact-runtime";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import { levelPrivateStateProvider } from "@midnight-ntwrk/midnight-js-level-private-state-provider";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import {
  createLedger9MidnightProvider,
  createLedger9WalletProvider,
  ZKConfigRegistry,
  type MidnightProvider,
  type MidnightProviders,
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
import { Contract } from "./managed/caller/contract/index.js";
import { recordingProofProvider, type CallPlacement } from "./placement.js";
import { witnesses, type CallerPrivateState } from "./witnesses.js";

export type CallerContract = Contract<CallerPrivateState>;
export type CallerCircuitId = keyof CallerContract["provableCircuits"] & string;
type CallerPrivateStateId = "rust-real-stack-caller";
export const CALLER_PRIVATE_STATE_ID: CallerPrivateStateId = "rust-real-stack-caller";
export type CallerProviders = MidnightProviders<
  CallerCircuitId,
  CallerPrivateStateId,
  CallerPrivateState
>;

const callerManagedPath = fileURLToPath(new URL("./managed/caller", import.meta.url));

export const callerCompiledContract = makeCompiledContract<CallerContract, CallerPrivateState>(
  "rust-real-stack-caller",
  Contract,
  witnesses,
  callerManagedPath,
);

// Transactions this provider set builds, and the recipes balancing them, expire 30 min out.
const TTL_SECONDS = 30 * 60;

export const providerConfig = (config: MidnightNodeConfig) => ({
  networkId: config.networkId,
  ttlSeconds: TTL_SECONDS,
});

// Both contracts cross-contract call only the Signet singleton, so every callee resolves to
// the module compile.mjs links beside them; the runtime still checks its verifier keys.
export const signetModuleProvider: ContractModuleProvider = {
  resolve: () => () => import("./managed/SignetSigner/contract/index.js"),
};

// Transactions cross between midnight-js and the facade as bytes, each sealing its own handle.
export function walletProviders(
  facade: WalletFacade,
  keys: AccountKeys,
): { walletProvider: WalletProvider; midnightProvider: MidnightProvider } {
  const walletProvider = createLedger9WalletProvider({
    getCoinPublicKey: () => keys.shieldedSecretKeys.coinPublicKey,
    getEncryptionPublicKey: () => keys.shieldedSecretKeys.encryptionPublicKey,
    async balanceTx(tx, ttl) {
      const recipe = await facade.balanceUnboundTransaction(
        facade.adoptTransaction(tx.serialize(), "Unbound"),
        { ttl: ttl ?? new Date(Date.now() + TTL_SECONDS * 1000) },
      );
      const signed = await facade.signRecipe(recipe, keys.unshieldedKeystore.signDataAsync);
      return facade.finalizeRecipe(signed);
    },
  });
  const midnightProvider = createLedger9MidnightProvider((tx) =>
    facade.submitTransaction(facade.adoptTransaction(tx.serialize(), "Finalized")),
  );
  return { walletProvider, midnightProvider };
}

export function buildCallerProviders(
  facade: WalletFacade,
  keys: AccountKeys,
  config: MidnightNodeConfig,
  databasePath: string,
  onPlacement: (placement: CallPlacement[]) => void,
): CallerProviders {
  const callerZk = new NodeZkConfigProvider<CallerCircuitId>(callerManagedPath);
  const signetZk = new NodeZkConfigProvider<string>(signetContractManagedPath);
  const wallet = walletProviders(facade, keys);
  return {
    privateStateProvider: levelPrivateStateProvider({
      midnightDbName: databasePath,
      privateStateStoreName: "caller-private-state",
      signingKeyStoreName: "caller-signing-keys",
      accountId: wallet.walletProvider.getCoinPublicKey(),
      privateStoragePasswordProvider: () => "MpcRealStack#2026!",
    }),
    publicDataProvider: indexerPublicDataProvider({
      queryURL: config.indexerUrl,
      subscriptionURL: config.indexerWsUrl,
    }),
    zkConfigProvider: callerZk,
    // `submitIsEvenRequest` calls into the Signet singleton, so one transaction carries a
    // proof per contract; the registry binds each call to its bundle by deployed verifier key.
    proofProvider: recordingProofProvider(
      httpClientProofProvider({
        url: config.proofServerUrl,
        zkConfigProvider: new ZKConfigRegistry([callerZk, signetZk]),
      }),
      onPlacement,
    ),
    ...wallet,
    config: providerConfig(config),
    contractModuleProvider: signetModuleProvider,
  };
}
