// Vault ledger reads: raw contract state from a public data provider, decoded
// with the generated `ledger()`. Takes the provider and address, so a browser
// client, the deploy tooling and a read-only script all drive it the same way.

import type { PublicDataProvider } from "@midnight-ntwrk/midnight-js/types";
import { bytesToHex, hexToBytes, toSignBidirectionalEventIndex } from "@sig-net/midnight";

import { ledger } from "./managed/erc20-vault/contract/index.js";

/** The decoded vault public ledger state, as the generated `ledger()` returns it. */
export type VaultLedgerState = ReturnType<typeof ledger>;

/**
 * Read + decode the vault's public ledger state.
 *
 * @param publicDataProvider - The provider to query raw contract state through.
 * @param vaultContractAddress - The deployed vault contract address.
 * @returns The decoded ledger state.
 * @throws {Error} If no contract state exists at `vaultContractAddress`.
 */
export async function readVaultLedger(
  publicDataProvider: PublicDataProvider,
  vaultContractAddress: string,
): Promise<VaultLedgerState> {
  const contractState = await publicDataProvider.queryContractState(vaultContractAddress);
  if (!contractState) {
    throw new Error(`no contract state found at ${vaultContractAddress} — is the address right?`);
  }
  return ledger(contractState.data);
}

/**
 * Read and print the vault's public ledger state: initialisation status, the
 * configured vault EVM address, the pinned EVM chain, and the pending signet
 * signature requests of the deposit and approve/withdraw maps. No proving keys
 * or transactions involved.
 *
 * @param publicDataProvider - The provider to query raw contract state through.
 * @param vaultContractAddress - The deployed vault contract address, as bare hex.
 * @throws {Error} If `vaultContractAddress` is not hex, or no contract state
 *   exists there.
 */
export async function printVaultState(
  publicDataProvider: PublicDataProvider,
  vaultContractAddress: string,
): Promise<void> {
  // Re-encode the address through bytes before it reaches the log: hexToBytes
  // rejects anything that is not hex, so an env secret misrouted into the
  // address variable is never printed.
  const address = bytesToHex(hexToBytes(vaultContractAddress));
  const state = await readVaultLedger(publicDataProvider, address);
  console.log(`vault contract:    ${address}`);
  console.log(`initialised:       ${String(state.initialised)}`);
  console.log(`vault EVM address: 0x${bytesToHex(state.vaultEvmAddress)}`);
  console.log(`EVM chain id:      ${String(state.evmChainId)}`);

  printRequestMap("deposit", state.depositEventMap);
  printRequestMap("approve/withdraw", state.signBidirectionalEventMap);
}

/**
 * Print one request map's pending entries under a heading naming the kinds it
 * holds.
 *
 * @param kinds - The request kinds recorded in this map.
 * @param map - The map to enumerate.
 */
function printRequestMap(
  kinds: string,
  map: Parameters<typeof toSignBidirectionalEventIndex>[0],
): void {
  const index = toSignBidirectionalEventIndex(map);
  console.log(`pending ${kinds} signature requests: ${String(index.size)}`);
  for (const [requestIdHex, request] of index) {
    console.log(`- ${requestIdHex} (requestNonce ${String(request.requestNonce)})`);
  }
}
