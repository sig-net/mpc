// Uniswap V3 constants for the swap flow: the pinned SwapRouter02 + QuoterV2 (Sepolia
// canonical, present on the pinned fork), the exactOutputSingle/approve ABI shapes, and a
// read-only QuoterV2 quote. Mirrors evm-transfer.ts for the swap leg.
import {
  MPC_PARAMS_BYTES,
  MPCDestination,
  MPCSignatureAlgorithm,
  pureCircuits as signetPureCircuits,
} from "@sig-net/midnight";
import { pureCircuits as vaultPureCircuits } from "../contract/src/index.ts";
import { UNISWAP_SWAP_ROUTER_02 } from "../contract/src/index.ts";
import type { ContractReadMethod } from "../test-harness/evm.ts";
import { ethers } from "ethers";

/** Uniswap V3 QuoterV2 on Sepolia — a read-only price oracle. */
export const UNISWAP_QUOTER_V2 = "0xEd1f6473345F45b75F8179591dd5bA1888cf2FB3";

/** exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160)) selector. */
export const EXACT_OUTPUT_SINGLE_SELECTOR = new Uint8Array([0x50, 0x23, 0xb4, 0xdf]);

/** approve(address,uint256) selector. */
export const APPROVE_SELECTOR = new Uint8Array([0x09, 0x5e, 0xa7, 0xb3]);

/** The allowance approveRouter grants, read from the compiled circuit so it cannot drift. */
export const MAX_APPROVE = vaultPureCircuits.unlimitedAllowance();

/** Gas ceiling of a V3 single-hop swap (~120-200k gas); the contract fixes this (vault pays). */
export const SWAP_GAS_LIMIT = 700_000n;

/** Max total fee per gas of a swap, wei (30 gwei). */
export const SWAP_MAX_FEE_PER_GAS = 30_000_000_000n;

/** Max priority fee per gas of a swap, wei (1 gwei). */
export const SWAP_MAX_PRIORITY_FEE_PER_GAS = 1_000_000_000n;

/**
 * The schema the MPC decodes the swap's EVM return against, read from the compiled circuit so
 * it cannot drift: exactOutputSingle returns a uint256 amountIn.
 */
export const SWAP_OUTPUT_SCHEMA = vaultPureCircuits.swapOutputSchema();

/**
 * The schema the MPC re-packs the decoded amountIn into for the attestation, read from the
 * compiled circuit so it cannot drift: a lean uint64, lossless as the swap caps amountIn at
 * amountInMaximum (<= Uint64).
 */
export const SWAP_RESPOND_SCHEMA = vaultPureCircuits.swapRespondSchema();

const QUOTER_ABI = [
  "function quoteExactOutputSingle((address tokenIn,address tokenOut,uint256 amount,uint24 fee,uint160 sqrtPriceLimitX96)) returns (uint256 amountIn,uint160 sqrtPriceX96After,uint32 initializedTicksCrossed,uint256 gasEstimate)",
];

/**
 * Whether the Uniswap router is deployed at `evmRpcUrl` (true on Sepolia + the fork).
 *
 * @param evmRpcUrl - The EVM JSON-RPC endpoint to probe.
 * @returns True when the SwapRouter02 has code at `evmRpcUrl`.
 */
export async function uniswapAvailable(evmRpcUrl: string): Promise<boolean> {
  const code = await new ethers.JsonRpcProvider(evmRpcUrl).getCode(UNISWAP_SWAP_ROUTER_02);
  return code !== "0x";
}

/**
 * Live QuoterV2 quote for exactOutputSingle (a read-only `eth_call`, no state change): the
 * `amountIn` needed to receive `amountOut`, and the `amountInMaximum` after applying
 * `slippageBps` (headroom ABOVE the quote). This is what the frontend shows and what the swap
 * circuit binds as the on-chain slippage cap (the router reverts if the real cost exceeds it).
 *
 * @param evmRpcUrl - The EVM JSON-RPC endpoint.
 * @param tokenIn - The token being sold.
 * @param tokenOut - The token being bought.
 * @param fee - The Uniswap V3 pool fee tier.
 * @param amountOut - The exact output amount to receive.
 * @param slippageBps - Basis points of headroom above the quote for the cap (default 100 = 1%).
 * @returns The quoted amountIn and the amountInMaximum cap after slippage.
 */
export async function quoteExactOutputSingle(
  evmRpcUrl: string,
  tokenIn: string,
  tokenOut: string,
  fee: bigint,
  amountOut: bigint,
  slippageBps = 100n, // 1%
): Promise<{ amountIn: bigint; amountInMaximum: bigint }> {
  const quoter = new ethers.Contract(
    UNISWAP_QUOTER_V2,
    QUOTER_ABI,
    new ethers.JsonRpcProvider(evmRpcUrl),
  );
  const [amountIn] = await quoter
    .getFunction<ContractReadMethod<[bigint, bigint, bigint, bigint]>>("quoteExactOutputSingle")
    .staticCall({ tokenIn, tokenOut, amount: amountOut, fee, sqrtPriceLimitX96: 0n });
  const amountInMaximum = (amountIn * (10_000n + slippageBps)) / 10_000n;
  return { amountIn, amountInMaximum };
}

/** The contract-fixed routing of a swap event (the swap-schema variant of VAULT_MPC_ROUTING). */
export const SWAP_MPC_ROUTING = {
  algo: MPCSignatureAlgorithm.ecdsa,
  dest: MPCDestination.unused,
  params: new Uint8Array(MPC_PARAMS_BYTES),
  caip2Id: signetPureCircuits.ethereumCaip2Id(),
  outputDeserializationSchema: SWAP_OUTPUT_SCHEMA,
  respondSerializationSchema: SWAP_RESPOND_SCHEMA,
};
