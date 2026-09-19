// `startRedeem`: record a stataToken.redeem(shares, vault, vault) SignBidirectionalEvent on the
// vault's REDEEM ledger map, surrendering `shares` of the stataUSDC vault coin (burned), to be
// signed with the VAULT's account and broadcast. The settle side lives in complete-redeem.ts.
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
import { readVaultLedger, STATA_USDC, VAULT_PATH_BYTES } from "../contract/src/index.ts";

import { logEvmFeeCap, logTokenAmount } from "./evm-logging.ts";
import {
  REDEEM_MPC_ROUTING,
  STATA_GAS_LIMIT,
  STATA_MAX_FEE_PER_GAS,
  STATA_MAX_PRIORITY_FEE_PER_GAS,
  STATA_REDEEM_SELECTOR,
} from "./evm-stata.ts";
import type { VaultContext } from "./vault-context.ts";
import { vaultTokenType } from "./vault-token.ts";

/** Options for {@link startRedeem}. */
export interface StartRedeemOptions {
  readonly shares: bigint;
  readonly evmNonce: bigint;
}

/**
 * Record the redeem request (stataToken.redeem(shares, vault, vault)) and return its id. The
 * burned coin is the stataUSDC vault token of exactly `shares`.
 *
 * @param context - The flow context.
 * @param options - The redeem parameters (shares, evmNonce).
 * @returns The recorded redeem request id.
 */
export async function startRedeem(
  context: VaultContext,
  options: StartRedeemOptions,
): Promise<RequestIdHex> {
  const before = await readVaultLedger(
    context.providers.publicDataProvider,
    context.vaultContractAddress,
  );
  if (!before.initialised)
    throw new Error("vault is not initialised, run the initialise flow first");

  const coin = {
    nonce: crypto.getRandomValues(new Uint8Array(32)),
    color: hexToBytes(vaultTokenType(STATA_USDC, context.vaultContractAddress)),
    value: options.shares,
  };

  await logTokenAmount(
    context.evmRpcUrl,
    STATA_USDC,
    context.evmVaultAddress,
    options.shares,
    "redeem amount",
  );
  const expectedRecord: SignBidirectionalEvent = {
    sender: { bytes: hexToBytes(stripHexPrefix(context.vaultContractAddress)) },
    requestNonce: before.signetRequestNonce,
    keyVersion: SIGNET_DEFAULT_KEY_VERSION,
    path: VAULT_PATH_BYTES,
    ...REDEEM_MPC_ROUTING,
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
          selector: STATA_REDEEM_SELECTOR,
          noWords: 3n,
          words: [
            numericAbiWord(options.shares),
            evmAddressAbiWord(before.vaultEvmAddress),
            evmAddressAbiWord(before.vaultEvmAddress),
          ],
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

  const result = await context.vault.callTx.startRedeem(
    options.evmNonce,
    SIGNET_DEFAULT_KEY_VERSION,
    options.shares,
    coin,
  );
  console.log(`redeem finalized in tx ${result.public.txId}`);

  const after = await readVaultLedger(
    context.providers.publicDataProvider,
    context.vaultContractAddress,
  );
  if (!toSignBidirectionalEventIndex(after.redeemEventMap).has(expectedIdHex)) {
    throw new Error(
      `recomputed redeem request id ${expectedIdHex} not found on the redeem ledger map`,
    );
  }
  console.log(`redeem request id: ${expectedIdHex}`);
  return expectedIdHex;
}
