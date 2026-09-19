// The vault's typed client surface: the circuit-id union, the private-state
// storage key, and the shapes a joined vault and its provider set take. Nothing
// runnable lives here on purpose. Composing a LIVE provider set is consumer
// territory, since it differs per environment (Node fs vs browser fetch for zk
// assets, LevelDB vs IndexedDB for private state, a wallet facade vs a
// connector API), so this package names the types and the consumer builds them.

import type { FoundContract } from "@midnight-ntwrk/midnight-js/contracts";
import type { MidnightProviders } from "@midnight-ntwrk/midnight-js/types";

import type { Contract } from "./managed/erc20-vault/contract/index.js";
import type { VaultPrivateState } from "./witnesses.ts";

/** The vault's provable circuit ids, straight from the generated contract. */
export type VaultCircuitId = keyof InstanceType<typeof Contract>["provableCircuits"];

/**
 * Literal of the private-state storage key. Just a string, but a single-value
 * union so the providers/`findDeployedContract` pairing is enforced by the
 * type system.
 */
export type VaultPrivateStateId = "erc20-vault";

/**
 * Key under which midnight-js persists the vault's private state locally.
 * Distinct per contract so two clients do not share an entry.
 */
export const VAULT_PRIVATE_STATE_ID: VaultPrivateStateId = "erc20-vault";

/** The full midnight-js provider set, typed to the vault. */
export type VaultProviders = MidnightProviders<
  // PCK: the union of the contract's provable circuit names.
  VaultCircuitId,
  // PSI: the private-state storage key literal.
  VaultPrivateStateId,
  // PS: the shape of the contract's private state object.
  VaultPrivateState
>;

/**
 * A joined vault contract handle: midnight-js's found-contract shape typed to
 * the vault's generated contract, so `callTx.initialise(...)` /
 * `callTx.deposit(...)` carry the real circuit signatures.
 */
export type DeployedVaultContract = FoundContract<Contract<VaultPrivateState>>;
