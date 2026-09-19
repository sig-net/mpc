// Curated export surface: the "sdk" face of the package.
// Everything the compiler emitted, the handwritten witnesses, the typed client
// surface, the ledger reads, the contract's EVM-side constants and the
// upstream per-network vault addresses. Nothing here
// may touch environment-specific APIs: this surface runs unchanged in a browser
// or a backend. Anything that cannot (the Node compiled-contract binding, a
// live provider set, deploy tooling) lives in a sibling package.

import { asciiPadded, bytesToHex, deriveEvmAddress, PATH_BYTES } from "@sig-net/midnight";

export * from "./contract-surface.ts";
export * from "./evm.ts";
export * from "./managed/erc20-vault/contract/index.js";
export * from "./vault-addresses.ts";
export * from "./vault-ledger.ts";
export * from "./witnesses.ts";

/**
 * The vault's own derivation path as the ledger stores it: every circuit that
 * records a vault-signed event sets the record's `path` to `pad(32, "vault")`.
 */
export const VAULT_PATH_BYTES = asciiPadded("vault", PATH_BYTES);

/**
 * The derivation-string rendering of {@link VAULT_PATH_BYTES}: the MPC renders
 * a record's path as the lowercase hex of the full 32 bytes, padding included,
 * and `deriveEvmAddress` takes the same rendering. Deriving the vault's EVM
 * account with any other rendering of "vault" yields an account the MPC will
 * never sign from.
 */
export const VAULT_PATH_HEX = bytesToHex(VAULT_PATH_BYTES);

/**
 * Derive the EVM account the MPC signs the vault's transactions from:
 * `f(MPC public key, this vault's contract address, {@link VAULT_PATH_HEX})`.
 * The one definition of that derivation, so the address a deploy seals in and
 * the address a test funds cannot drift apart.
 *
 * @param mpcSecp256k1PublicKey - The MPC network's secp256k1 public key (SEC1 hex).
 * @param vaultContractAddress - The deployed vault contract's address.
 * @returns The vault's EVM address, 0x-prefixed.
 */
export function deriveVaultEvmAddress(
  mpcSecp256k1PublicKey: string,
  vaultContractAddress: string,
): string {
  return deriveEvmAddress(mpcSecp256k1PublicKey, vaultContractAddress, VAULT_PATH_HEX);
}

// THIS contract's signet ledger layout (declaration order in
// erc20-vault.compact): each request kind owns a SignBidirectionalEventMap, and
// `signetRequestNonce` keeps otherwise identical requests hashing apart. A
// client contract is free to place its event maps at any field: every raw
// reader takes the resolved ledger-tree path explicitly, and the path must
// match the `requestsPath` the contract packs into its notifications. The
// compiler records each field's path as its "index" in
// managed/erc20-vault/compiler/contract-info.json.

// The vault has 20 ledger fields, past the 15-field flat limit, so the compiler
// chunks the state tree two levels deep. Every path below is therefore
// [chunk, offset] (depth 2), and the request circuits pack the same as
// requestsPathDepth 2. Chunk 0 holds fields 0–4, chunk 1 holds fields 5–19.

/**
 * Resolved ledger-tree path of `signBidirectionalEventMap` (ledger field 0),
 * which holds the approve and withdraw requests. The same path `approveStata`,
 * `approveRouter` and `startWithdraw` pack as depth 2 + [0, 0, 0, 0].
 */
export const VAULT_REQUESTS_PATH: readonly number[] = [0, 0];

/** Resolved ledger-tree path of `signetRequestNonce` (ledger field 3). */
export const VAULT_NONCE_PATH: readonly number[] = [0, 3];

/**
 * Resolved ledger-tree path of `depositEventMap` (ledger field 8). Deposits
 * register their notification in this SEPARATE map, so the deposit flow reads
 * MPC responses from this path. Matches the depth 2 + `requestsPath`
 * [1, 3, 0, 0] the `startDeposit` circuit packs.
 */
export const VAULT_DEPOSIT_REQUESTS_PATH: readonly number[] = [1, 3];

/**
 * Resolved ledger-tree path of `swapEventMap` (ledger field 12). Swaps register
 * their notification in this SEPARATE map (sized for a 7-word exactOutputSingle),
 * so the swap flow reads MPC responses from this path. Matches the depth 2 +
 * `requestsPath` [1, 7, 0, 0] the `startSwap` circuit packs.
 */
export const VAULT_SWAP_REQUESTS_PATH: readonly number[] = [1, 7];

/** Resolved ledger-tree path of `supplyEventMap` (ledger field 16). */
export const VAULT_SUPPLY_REQUESTS_PATH: readonly number[] = [1, 11];

/** Resolved ledger-tree path of `redeemEventMap` (ledger field 18). */
export const VAULT_REDEEM_REQUESTS_PATH: readonly number[] = [1, 13];
