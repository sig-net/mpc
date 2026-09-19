// `startSupply`: record a stataToken.deposit(amount, vault) SignBidirectionalEvent on the
// vault's SUPPLY ledger map, surrendering `amount` of the underlying (USDC) vault coin
// (burned), to be signed with the VAULT's account and broadcast. Exact-input, so there is no
// change. The settle side lives in complete-supply.ts.
import {
  calculateRequestId,
  evmAddressAbiWord,
  hexToBytes,
  numericAbiWord,
  type RequestIdHex,
  requestIdHex,
  type SignBidirectionalEvent,
  SIGNET_DEFAULT_KEY_VERSION,
  stripHexPrefix,
  toSignBidirectionalEventIndex,
  TxParamType,
} from "@sig-net/midnight";
import { AAVE_USDC, readVaultLedger, VAULT_PATH_BYTES } from "../contract/src/index.ts";

import { logEvmFeeCap, logTokenAmount } from "./evm-logging.ts";
import {
  STATA_DEPOSIT_SELECTOR,
  STATA_GAS_LIMIT,
  STATA_MAX_FEE_PER_GAS,
  STATA_MAX_PRIORITY_FEE_PER_GAS,
  SUPPLY_MPC_ROUTING,
} from "./evm-stata.ts";
import type { VaultContext } from "./vault-context.ts";
import { vaultTokenType } from "./vault-token.ts";

/** Options for {@link startSupply}. */
export interface StartSupplyOptions {
  readonly amount: bigint;
  readonly evmNonce: bigint;
}

/**
 * Record the supply request (stataToken.deposit(amount, vault)) and return its id. The burned
 * coin is the underlying (USDC) vault token of exactly `amount`.
 *
 * @param context - The flow context.
 * @param options - The supply parameters (amount, evmNonce).
 * @returns The recorded supply request id.
 */
export async function startSupply(
  context: VaultContext,
  options: StartSupplyOptions,
): Promise<RequestIdHex> {
  const before = await readVaultLedger(
    context.providers.publicDataProvider,
    context.vaultContractAddress,
  );
  if (!before.initialised)
    throw new Error("vault is not initialised, run the initialise flow first");

  const coin = {
    nonce: crypto.getRandomValues(new Uint8Array(32)),
    color: hexToBytes(vaultTokenType(AAVE_USDC, context.vaultContractAddress)),
    value: options.amount,
  };

  // The record the contract composes: vault path/sender, stataToken `to`, contract-fixed gas,
  // deposit(amount, receiver=vault).
  await logTokenAmount(
    context.evmRpcUrl,
    AAVE_USDC,
    context.evmVaultAddress,
    options.amount,
    "supply amount",
  );
  const expectedRecord: SignBidirectionalEvent = {
    sender: { bytes: hexToBytes(stripHexPrefix(context.vaultContractAddress)) },
    requestNonce: before.signetRequestNonce,
    keyVersion: SIGNET_DEFAULT_KEY_VERSION,
    path: VAULT_PATH_BYTES,
    ...SUPPLY_MPC_ROUTING,
    txParamType: TxParamType.evmType2,
    txParams: {
      to: before.stataToken,
      chainId: before.evmChainId,
      nonce: options.evmNonce,
      gasLimit: STATA_GAS_LIMIT,
      maxFeePerGas: STATA_MAX_FEE_PER_GAS,
      maxPriorityFeePerGas: STATA_MAX_PRIORITY_FEE_PER_GAS,
      value: 0n,
      accessListEntryCount: 0n,
      accessList: [],
      calldata: {
        is_some: true,
        value: {
          selector: STATA_DEPOSIT_SELECTOR,
          noWords: 2n,
          words: [numericAbiWord(options.amount), evmAddressAbiWord(before.vaultEvmAddress)],
        },
      },
    },
  };
  const expectedIdHex = requestIdHex(calculateRequestId(expectedRecord));
  logEvmFeeCap(
    expectedIdHex,
    context.evmVaultAddress,
    expectedRecord.txParams.gasLimit,
    expectedRecord.txParams.maxFeePerGas,
    expectedRecord.txParams.maxPriorityFeePerGas,
  );

  const result = await context.vault.callTx.startSupply(
    options.evmNonce,
    SIGNET_DEFAULT_KEY_VERSION,
    options.amount,
    coin,
  );
  console.log(`supply finalized in tx ${result.public.txId}`);

  const after = await readVaultLedger(
    context.providers.publicDataProvider,
    context.vaultContractAddress,
  );
  if (!toSignBidirectionalEventIndex(after.supplyEventMap).has(expectedIdHex)) {
    throw new Error(
      `recomputed supply request id ${expectedIdHex} not found on the supply ledger map`,
    );
  }
  console.log(`supply request id: ${expectedIdHex}`);
  return expectedIdHex;
}
