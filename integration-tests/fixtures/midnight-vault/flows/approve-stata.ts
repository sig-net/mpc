// `approveStata`: record an approve(stataToken, ~unlimited) SignBidirectionalEvent on the
// vault's ledger (field 0), have the MPC sign it with the VAULT's account, and broadcast it.
// Sign-only (nothing minted, no settle circuit), so the round trip ends at the broadcast. The
// approve is called ON the pinned underlying (USDC), spender = the pinned stataToken wrapper,
// so the wrapper can pull USDC during supply.
import {
  asciiPadded,
  calculateRequestId,
  evmAddressAbiWord,
  hexToBytes,
  numericAbiWord,
  PATH_BYTES,
  type RequestIdHex,
  requestIdHex,
  type SignBidirectionalEvent,
  SIGNET_DEFAULT_KEY_VERSION,
  stripHexPrefix,
  toSignBidirectionalEventIndex,
  TxParamType,
} from "@sig-net/midnight";
import { AAVE_USDC, evmAddressBytes, readVaultLedger, STATA_USDC } from "../contract/src/index.ts";
import { type ContractReadMethod, getTransactionNonce } from "../test-harness/evm.ts";
import { logSkip } from "../test-harness/output.ts";

import { logEvmFeeCap } from "./evm-logging.ts";
import { APPROVE_SELECTOR, MAX_APPROVE } from "./evm-stata.ts";
import {
  ERC20_TRANSFER_GAS_LIMIT,
  ERC20_TRANSFER_MAX_FEE_PER_GAS,
  ERC20_TRANSFER_MAX_PRIORITY_FEE_PER_GAS,
} from "./evm-transfer.ts";
import { VAULT_MPC_ROUTING } from "./mpc-routing.ts";
import type { VaultContext } from "./vault-context.ts";
import type { VaultSession } from "./vault-session.ts";
import { broadcastEvm } from "./broadcast-evm.ts";
import { pollSignatureResponse } from "./poll-signature-response.ts";

const MINUTE = 60_000;

/**
 * Record the approveStata request and return its id.
 *
 * @param context - The flow context.
 * @param evmNonce - The vault EVM account nonce for the approve transaction.
 * @returns The recorded request id.
 */
export async function approveStata(context: VaultContext, evmNonce: bigint): Promise<RequestIdHex> {
  const before = await readVaultLedger(
    context.providers.publicDataProvider,
    context.vaultContractAddress,
  );
  if (!before.initialised)
    throw new Error("vault is not initialised, run the initialise flow first");

  // approve(stataToken, MAX) on the underlying USDC, signed with the vault account (path
  // "vault"), the same 2-word map + bool schema as a transfer.
  const expectedRecord: SignBidirectionalEvent = {
    sender: { bytes: hexToBytes(stripHexPrefix(context.vaultContractAddress)) },
    requestNonce: before.signetRequestNonce,
    keyVersion: SIGNET_DEFAULT_KEY_VERSION,
    path: asciiPadded("vault", PATH_BYTES),
    ...VAULT_MPC_ROUTING,
    txParamType: TxParamType.evmType2,
    txParams: {
      to: evmAddressBytes(AAVE_USDC),
      chainId: before.evmChainId,
      nonce: evmNonce,
      gasLimit: ERC20_TRANSFER_GAS_LIMIT,
      maxFeePerGas: ERC20_TRANSFER_MAX_FEE_PER_GAS,
      maxPriorityFeePerGas: ERC20_TRANSFER_MAX_PRIORITY_FEE_PER_GAS,
      value: 0n,
      accessListEntryCount: 0n,
      accessList: [],
      calldata: {
        is_some: true,
        value: {
          selector: APPROVE_SELECTOR,
          noWords: 2n,
          words: [evmAddressAbiWord(evmAddressBytes(STATA_USDC)), numericAbiWord(MAX_APPROVE)],
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
  const result = await context.vault.callTx.approveStata(evmNonce, SIGNET_DEFAULT_KEY_VERSION);
  console.log(`approveStata finalized in tx ${result.public.txId}`);

  const after = await readVaultLedger(
    context.providers.publicDataProvider,
    context.vaultContractAddress,
  );
  if (!toSignBidirectionalEventIndex(after.signBidirectionalEventMap).has(expectedIdHex)) {
    throw new Error(`recomputed approveStata request id ${expectedIdHex} not found on the ledger`);
  }
  return expectedIdHex;
}

/**
 * Ensure the vault account has approved the stataToken to pull the underlying: read the live
 * allowance, and if it is zero run the approve leg (request -> sign -> broadcast; no settle).
 * Idempotent and global.
 *
 * @param session - The vault session.
 */
export async function ensureStataApproved(session: VaultSession): Promise<void> {
  const context = await session.vaultContext();
  const { ethers } = await import("ethers");
  const token = new ethers.Contract(
    AAVE_USDC,
    ["function allowance(address,address) view returns (uint256)"],
    new ethers.JsonRpcProvider(context.evmRpcUrl),
  );
  const allowance: bigint = await token.getFunction<ContractReadMethod<bigint>>("allowance")(
    context.evmVaultAddress,
    STATA_USDC,
  );
  if (allowance > 0n) {
    logSkip("approveStata", `stataToken already approved (allowance ${String(allowance)})`);
    return;
  }

  const evmNonce = await getTransactionNonce(context.evmRpcUrl, context.evmVaultAddress);
  const requestId = await approveStata(context, evmNonce);
  const signed = await pollSignatureResponse(context, {
    requestId,
    intervalMs: 1000,
    timeoutMs: 2 * MINUTE,
    expectedSigner: context.evmVaultAddress,
  });
  await broadcastEvm(context, { transaction: signed });
  console.log("stataToken approved to pull the underlying");
}
