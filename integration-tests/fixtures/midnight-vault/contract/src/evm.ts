// The EVM side of the vault's interface: the contracts it trades and lends
// through, and the byte conversion every EVM address crosses to reach a
// circuit. The addresses are the Sepolia canonicals, which is what the example
// runs against (its local stack forks Sepolia), and `initialise` pins whichever
// values a deployment chooses into the contract.

import { hexToBytes } from "@sig-net/midnight";

/** Uniswap V3 SwapRouter02 on Sepolia: the router the swap circuits call. */
export const UNISWAP_SWAP_ROUTER_02 = "0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E";

/** Aave v3 Sepolia USDC: the underlying the supply circuit lends. */
export const AAVE_USDC = "0x94a9D9AC8a22534E3FaCa9F4e7F2E2cf85d5E4C8";

/** Aave v3 Sepolia stataUSDC: the non-rebasing ERC-4626 wrapper of {@link AAVE_USDC}. */
export const STATA_USDC = "0x8A88124522dbBF1E56352ba3DE1d9F78C143751e";

/**
 * Decode a 20-byte 0x-prefixed hex EVM address to the raw bytes a circuit's
 * `Bytes<20>` argument takes.
 *
 * @param hex - The address, e.g. `0xA0c8…1514`.
 * @returns The 20 address bytes.
 * @throws {Error} If the input is not a 20-byte 0x hex string.
 */
export function evmAddressBytes(hex: string): Uint8Array {
  if (!/^0x[0-9a-fA-F]{40}$/.test(hex)) {
    throw new Error(`expected a 20-byte 0x hex EVM address; got "${hex}".`);
  }
  return hexToBytes(hex);
}
