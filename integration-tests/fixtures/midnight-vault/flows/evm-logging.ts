import { getErc20Balance } from "../test-harness/evm.ts";
import { formatEther, formatUnits } from "ethers";

/**
 * Describe a funding requirement without losing the atomic values.
 *
 * @param available - Current balance in atomic units.
 * @param required - Required balance in atomic units.
 * @param decimals - Decimal places of the asset.
 * @param asset - Asset identifier and unit.
 * @returns Available, required and missing amounts.
 */
export function fundingSummary(
  available: bigint,
  required: bigint,
  decimals: number,
  asset: string,
): string {
  const shortfall: bigint = required > available ? required - available : 0n;
  return `available ${formatUnits(available, decimals)} ${asset}, required ${formatUnits(required, decimals)} ${asset}, shortfall ${formatUnits(shortfall, decimals)} ${asset}`;
}

/**
 * Report the signed fee envelope separately from an execution estimate.
 *
 * @param label - Request or operation identifier.
 * @param payer - Account that pays EVM fees.
 * @param gasLimit - Maximum gas units.
 * @param maxFeePerGas - Maximum total wei per gas.
 * @param maxPriorityFeePerGas - Maximum priority wei per gas.
 */
export function logEvmFeeCap(
  label: string,
  payer: string,
  gasLimit: bigint,
  maxFeePerGas: bigint,
  maxPriorityFeePerGas: bigint,
): void {
  console.log(
    `${label}: EVM payer ${payer}, gas limit ${String(gasLimit)}, fee cap ${formatUnits(maxFeePerGas, "gwei")} gwei, priority cap ${formatUnits(maxPriorityFeePerGas, "gwei")} gwei, maximum gas fee ${formatEther(gasLimit * maxFeePerGas)} ETH`,
  );
}

/**
 * Report a token amount using that token's decimals.
 *
 * @param rpcUrl - EVM endpoint.
 * @param token - Token contract address.
 * @param account - Account used for the metadata read.
 * @param amount - Amount in atomic units.
 * @param label - Meaning of this amount.
 */
export async function logTokenAmount(
  rpcUrl: string,
  token: string,
  account: string,
  amount: bigint,
  label: string,
): Promise<void> {
  console.log(`${label}: ${await formatTokenAmount(rpcUrl, token, account, amount)}`);
}

/**
 * Format an amount using token metadata, with atomic units as the fallback.
 *
 * @param rpcUrl - EVM endpoint.
 * @param token - Token contract address.
 * @param account - Account used for the metadata read.
 * @param amount - Atomic amount.
 * @returns Token amount with its asset identifier and explicit units.
 */
export async function formatTokenAmount(
  rpcUrl: string,
  token: string,
  account: string,
  amount: bigint,
): Promise<string> {
  try {
    const { decimals } = await getErc20Balance(rpcUrl, token, account);
    return `${formatUnits(amount, decimals)} of ${token} (${String(amount)} base units)`;
  } catch {
    return `${String(amount)} base units of ${token} (token decimals unavailable)`;
  }
}
