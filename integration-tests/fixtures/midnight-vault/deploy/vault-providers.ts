// The vault's midnight-js provider set: the zk-config paths the proof provider
// reads keys from, the private-state store, and the wallet adapter. The types
// it satisfies come from the contract package, the binding from
// vault-contract-binding.ts, and the midnight-js provider adapters from
// @sig-net/midnight-examples-lib. Both the deploy flows and the integration
// tests compose this and call `findDeployedContract(providers, ...)`.

import { existsSync } from "node:fs";
import { join } from "node:path";

import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import { levelPrivateStateProvider } from "@midnight-ntwrk/midnight-js-level-private-state-provider";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import {
  type AccountKeys,
  type MidnightNodeConfig,
  signetContractManagedPath,
  type WalletFacade,
} from "@sig-net/midnight-contract-deploy";
import type { VaultCircuitId, VaultProviders } from "../contract/src/index.ts";
import {
  createCrossContractProofServerProvider,
  createWalletAndMidnightProvider,
  type ProofServerObserver,
} from "../lib/midnight-providers.ts";

import { VAULT_MANAGED_PATH } from "./vault-contract-binding.ts";

/**
 * Build the midnight-js provider set for the vault. Proving reads the vault's
 * keys from the contract package's compiler output on every network, so the
 * checkout must hold `yarn compile:erc20-vault:zk` output.
 *
 * @param facade - A started (and synced) wallet facade, see the SDK's `withSyncedWalletFacade`.
 * @param keys - The key material of the same wallet, for balancing and signing.
 * @param config - The Midnight network endpoints to run against.
 * @param proofObserver - Called after every proof-server /check and /prove round trip.
 * @returns The provider set to hand to `findDeployedContract` / `deployContract`.
 * @throws {Error} If the vault's compiler output carries no keys.
 */
export function buildVaultProviders(
  facade: WalletFacade,
  keys: AccountKeys,
  config: MidnightNodeConfig,
  proofObserver?: ProofServerObserver,
): VaultProviders {
  // Without this check the missing keys surface as an ENOENT inside the proof
  // provider on the first circuit call, with no hint at the fix.
  if (!existsSync(join(VAULT_MANAGED_PATH, "keys"))) {
    throw new Error(
      `no prover keys under ${VAULT_MANAGED_PATH}: run \`yarn compile:erc20-vault:zk\` first`,
    );
  }

  // Retrieves the ZK artifacts of a contract needed to create proofs.
  // Key methods: getProverKey(id), getVerifierKey(id), getZKIR(id), with id
  // typed to the circuit-name union.
  const vaultZkConfigProvider = new NodeZkConfigProvider<VaultCircuitId>(VAULT_MANAGED_PATH);

  // The callee (signet contract) circuits, resolved for the cross-contract
  // proof provider so deposit's whole call tree proves.
  const signetZkConfigProvider = new NodeZkConfigProvider<string>(signetContractManagedPath);

  // The wallet, adapted to midnight-js's balancer + submitter interfaces
  // (the facade itself does not implement WalletProvider/MidnightProvider).
  const walletAndMidnightProvider = createWalletAndMidnightProvider(facade, keys, config.networkId);
  const accountId = walletAndMidnightProvider.getCoinPublicKey();

  return {
    // Manages the private state of a contract, plus contract-maintenance
    // signing keys.
    // Key methods: get(id)→PS|null, set(id, PS), remove, clear,
    //              getSigningKey/setSigningKey (keyed by contract address),
    //              exportPrivateStates/importPrivateStates.
    // Storage is LevelDB (browser: IndexedDB): clearing the store permanently
    // destroys it, and the package itself warns against production use where
    // loss matters. Fine here: our private state is just the identity secret
    // the caller already holds in env/config, so nothing is lost with the DB.
    privateStateProvider: levelPrivateStateProvider({
      // Sublevel for private states, keyed by privateStateId.
      // Default 'private-states' (in db 'midnight-level-db').
      // Set to prevent collision with other dApps.
      privateStateStoreName: "vault-private-states",

      // Sublevel for contract-maintenance signing keys, keyed by contract
      // address, written on deployContract. Default 'signing-keys'.
      // Set to prevent collision with other dApps.
      signingKeyStoreName: "vault-signing-keys",

      // Account identifier used to scope storage: isolates data between
      // different accounts/wallets using the same database.
      accountId,

      // Returns the password (sync or async) used to encrypt BOTH stores.
      // Must pass validatePassword: ≥16 chars, ≥3 of {upper,lower,digit,
      // special}, no 3+ repeated chars, no 4+ sequential runs, else
      // PasswordValidationError at runtime. A constant in source is
      // obfuscation, not secrecy, acceptable here only because nothing
      // sensitive is stored. (Kept constant: hex derived from the account id
      // could trip the repeat/sequence rules, and per-account isolation
      // already comes from `accountId` scoping.)
      privateStoragePasswordProvider: () => "&*(BHJqwe419-erc20Vault",
    }),

    // Retrieves public data from the blockchain.
    // Key methods: queryContractState(addr), watchForContractState,
    // contractStateObservable(addr).
    publicDataProvider: indexerPublicDataProvider({
      queryURL: config.indexerUrl,
      subscriptionURL: config.indexerWsUrl,
    }),

    // midnight-js's provider record holds exactly one, so the SLOT keeps the
    // bare kind name. The local binding is qualified because a second one
    // (the signet callee's) exists beside it.
    zkConfigProvider: vaultZkConfigProvider,

    // Creates proven, unbalanced transactions (proves the contract-call
    // transcript). This is NOT the wallet's proving config: the facade's
    // proof server only proves the wallet's own balancing additions when it
    // finalizes a recipe. The call transcript is proven here first. Spans the
    // vault AND the signet contract so deposit's cross-contract call
    // resolves keys for the whole call tree.
    proofProvider: createCrossContractProofServerProvider(
      config.proofServerUrl,
      [vaultZkConfigProvider, signetZkConfigProvider],
      proofObserver,
    ),

    // Creates proven, balanced transactions.
    walletProvider: walletAndMidnightProvider,

    // Submits proven, balanced transactions to the network.
    midnightProvider: walletAndMidnightProvider,
  };
}
