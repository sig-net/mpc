// EVM read-only helpers for funding preflights and setup checks (per the repo
// convention, ethers is the Ethereum library).

import type { ContractMethod, ContractTransactionResponse } from "ethers";
import { Contract, JsonRpcProvider } from "ethers";

/**
 * A read-only ABI method reached through ethers' `getFunction` accessor.
 *
 * A `Contract` exposes its ABI methods through a string index signature, which
 * `noUncheckedIndexedAccess` types as possibly-undefined, so `erc20.balanceOf(…)`
 * cannot be invoked directly. `getFunction` is ethers' own typed accessor for
 * that call. Its generic pins argument tuples to a loose list, so the precision
 * worth expressing here is the return type.
 */
export type ContractReadMethod<R> = ContractMethod<unknown[], R, R>;

/**
 * A state-changing ABI method reached through ethers' `getFunction` accessor,
 * resolving to the sent transaction. See {@link ContractReadMethod} for why
 * `getFunction` stands in for a direct method access.
 */
export type ContractWriteMethod = ContractMethod<
  unknown[],
  ContractTransactionResponse,
  ContractTransactionResponse
>;

/**
 * Read the bytecode deployed at an address.
 *
 * @param rpcUrl - JSON-RPC endpoint (e.g. `EVM_RPC_URL`).
 * @param address - The address to query.
 * @returns The deployed code as a hex string — `"0x"` when nothing is deployed there.
 */
export async function getDeployedCode(rpcUrl: string, address: string): Promise<string> {
  const provider = new JsonRpcProvider(rpcUrl);
  try {
    return await provider.getCode(address);
  } finally {
    provider.destroy();
  }
}

const ERC20_READ_ABI = [
  "function balanceOf(address) view returns (uint256)",
  "function decimals() view returns (uint8)",
];

/**
 * Read an address's native ETH balance.
 *
 * @param rpcUrl - JSON-RPC endpoint (e.g. `EVM_RPC_URL`).
 * @param address - The account to query.
 * @returns Balance in wei.
 */
export async function getEthBalance(rpcUrl: string, address: string): Promise<bigint> {
  const provider = new JsonRpcProvider(rpcUrl);
  try {
    return await provider.getBalance(address);
  } finally {
    provider.destroy();
  }
}

/**
 * Read an address's next transaction nonce (pending count).
 *
 * @param rpcUrl - JSON-RPC endpoint (e.g. `EVM_RPC_URL`).
 * @param address - The account to query.
 * @returns The nonce for the account's next transaction.
 */
export async function getTransactionNonce(rpcUrl: string, address: string): Promise<bigint> {
  const provider = new JsonRpcProvider(rpcUrl);
  try {
    return BigInt(await provider.getTransactionCount(address, "pending"));
  } finally {
    provider.destroy();
  }
}

/**
 * Whether a transaction hash has already mined (a receipt exists, succeeded
 * or reverted). Lets reruns distinguish a fresh broadcast from an idempotent
 * re-broadcast of an already-mined transaction.
 *
 * @param rpcUrl - JSON-RPC endpoint (e.g. `EVM_RPC_URL`).
 * @param txHash - The transaction hash to look up.
 * @returns `true` when a receipt exists for `txHash`.
 */
export async function isTransactionMined(rpcUrl: string, txHash: string): Promise<boolean> {
  const provider = new JsonRpcProvider(rpcUrl);
  try {
    return (await provider.getTransactionReceipt(txHash)) !== null;
  } finally {
    provider.destroy();
  }
}

/**
 * Read an address's ERC20 token balance along with the token's decimals.
 *
 * @param rpcUrl - JSON-RPC endpoint (e.g. `EVM_RPC_URL`).
 * @param token - The ERC20 contract address.
 * @param holder - The account to query.
 * @returns The raw balance and the token's `decimals()`.
 */
export async function getErc20Balance(
  rpcUrl: string,
  token: string,
  holder: string,
): Promise<{ balance: bigint; decimals: number }> {
  const provider = new JsonRpcProvider(rpcUrl);
  try {
    const erc20 = new Contract(token, ERC20_READ_ABI, provider);
    const [balance, decimals] = await Promise.all([
      erc20.getFunction<ContractReadMethod<bigint>>("balanceOf")(holder),
      erc20.getFunction<ContractReadMethod<bigint>>("decimals")(),
    ]);
    return { balance, decimals: Number(decimals) };
  } finally {
    provider.destroy();
  }
}
