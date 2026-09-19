// `startWithdraw`: the first half of the withdraw flow. Surrender a shielded
// vault coin (burned by the contract) and record a SignBidirectionalEvent
// asking the MPC to sign an EVM `transfer(destination, amount)` on the
// ERC20, sent from the VAULT's derived address (path = "vault"). The request
// id is recomputed off-chain with the library's TS twin of the request-id
// circuit and asserted against the ledger map key before it is returned.
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
import { VAULT_PATH_BYTES } from "../contract/src/index.ts";
import { evmAddressBytes, readVaultLedger } from "../contract/src/index.ts";

import { logEvmFeeCap, logTokenAmount } from "./evm-logging.ts";
import {
  ERC20_TRANSFER_GAS_LIMIT,
  ERC20_TRANSFER_MAX_FEE_PER_GAS,
  ERC20_TRANSFER_MAX_PRIORITY_FEE_PER_GAS,
  ERC20_TRANSFER_SELECTOR,
} from "./evm-transfer.ts";
import { VAULT_MPC_ROUTING } from "./mpc-routing.ts";
import type { VaultContext } from "./vault-context.ts";
import { vaultTokenType } from "./vault-token.ts";

/** Options for {@link startWithdraw}. */
export interface StartWithdrawOptions {
  /** Withdraw amount in ERC20 base units. */
  readonly amount: bigint;
  /** Destination EVM address (20-byte 0x hex) receiving the ERC20. */
  readonly destEvmAddress: string;
  /** Nonce of the VAULT's derived EVM account (the withdraw tx sender). */
  readonly evmNonce: bigint;
}

/**
 * Call the vault's `startWithdraw` circuit on the deployed contract and return
 * the resulting request id.
 *
 * Surrenders a shielded vault coin of exactly `amount` — the coin's color
 * comes from the compiled `vaultTokenDomainSeparator` circuit plus the
 * runtime's `rawTokenType`, and midnight-js funds its value from the caller's
 * shielded balance when it balances the call. The circuit pins a refund
 * COMMITMENT of this wallet's identity secret (never a public key), so only
 * this caller can pull a refund in `completeWithdraw` if the EVM transfer
 * fails. The circuit takes only the vault account's nonce, the key version,
 * the withdraw arguments and the coin: the vault pays the withdraw gas, so
 * the whole fee envelope is contract-fixed (mirrored here by the
 * `ERC20_TRANSFER_*` constants — keep in lockstep). The expected request
 * record is reconstructed off-chain, its id computed with the library's
 * `calculateRequestId` TS twin, and asserted present as a ledger map key
 * after the call.
 *
 * @param context - The flow context.
 * @param options - The withdraw arguments.
 * @returns The request id as 64-char lowercase hex.
 * @throws {Error} If an option is invalid, the vault is uninitialised, the caller's
 *   shielded balance cannot cover `options.amount`, or the recomputed id
 *   does not appear on the ledger.
 */
export async function startWithdraw(
  context: VaultContext,
  options: StartWithdrawOptions,
): Promise<RequestIdHex> {
  if (options.amount <= 0n) {
    throw new Error(`amount must be a positive integer; got ${String(options.amount)}.`);
  }
  if (options.evmNonce < 0n) {
    throw new Error(`evmNonce must be non-negative; got ${String(options.evmNonce)}.`);
  }
  const destEvmAddress = evmAddressBytes(options.destEvmAddress);
  const erc20 = evmAddressBytes(context.erc20Address);
  console.log(`vault contract: ${context.vaultContractAddress}`);
  console.log(`erc20:          ${context.erc20Address}`);
  console.log(`destination:    ${options.destEvmAddress}`);

  // Pre-call ledger read: the request nonce the contract will use and the
  // pinned chain config.
  await logTokenAmount(
    context.evmRpcUrl,
    context.erc20Address,
    context.evmUserAddress,
    options.amount,
    "start-withdraw amount",
  );
  const before = await readVaultLedger(
    context.providers.publicDataProvider,
    context.vaultContractAddress,
  );
  if (!before.initialised) {
    throw new Error("vault is not initialised, run the initialise flow first");
  }
  const requestNonce = before.signetRequestNonce;

  // The surrendered coin: the vault token for THIS erc20, of exactly
  // `amount`, under a fresh random nonce.
  const coin = {
    nonce: crypto.getRandomValues(new Uint8Array(32)),
    color: hexToBytes(vaultTokenType(context.erc20Address, context.vaultContractAddress)),
    value: options.amount,
  };

  const keyVersion = SIGNET_DEFAULT_KEY_VERSION;

  // The record the contract will store, reconstructed byte for byte: the
  // event's own sender (the vault contract, kernel.self() in-circuit), the
  // fully contract-composed envelope (the pinned chain, the contract-fixed
  // gas), the contract-built `transfer(destination, amount)` calldata (the
  // raw selector, the ABI-ready big-endian address and amount words, as broadcast), the
  // vault's own 32-byte derivation path, and the contract-fixed routing.
  const expectedRecord: SignBidirectionalEvent = {
    sender: { bytes: hexToBytes(stripHexPrefix(context.vaultContractAddress)) },
    requestNonce,
    keyVersion,
    path: VAULT_PATH_BYTES,
    ...VAULT_MPC_ROUTING,
    txParamType: TxParamType.evmType2,
    txParams: {
      to: erc20,
      chainId: before.evmChainId,
      nonce: options.evmNonce,
      gasLimit: ERC20_TRANSFER_GAS_LIMIT,
      maxFeePerGas: ERC20_TRANSFER_MAX_FEE_PER_GAS,
      maxPriorityFeePerGas: ERC20_TRANSFER_MAX_PRIORITY_FEE_PER_GAS,
      value: 0n,
      accessListEntryCount: 0n,
      accessList: [],
      calldata: {
        is_some: true,
        value: {
          selector: ERC20_TRANSFER_SELECTOR,
          noWords: 2n,
          words: [evmAddressAbiWord(destEvmAddress), numericAbiWord(options.amount)],
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

  const result = await context.vault.callTx.startWithdraw(
    options.evmNonce,
    keyVersion,
    {
      erc20Address: erc20,
      amount: options.amount,
      destEvmAddress,
    },
    coin,
  );
  console.log(`withdraw finalized in tx ${result.public.txId}`);

  // The ledger map key IS the record's transientHash digest: recomputing it
  // off-chain and finding it on the ledger proves both sides agree on every
  // byte of the event.
  const after = await readVaultLedger(
    context.providers.publicDataProvider,
    context.vaultContractAddress,
  );
  const index = toSignBidirectionalEventIndex(after.signBidirectionalEventMap);
  if (!index.has(expectedIdHex)) {
    throw new Error(
      `recomputed request id ${expectedIdHex} not found on the ledger — ` +
        `present ids: [${[...index.keys()].join(", ")}] (was another request submitted concurrently?)`,
    );
  }
  console.log(`request id:     ${expectedIdHex}`);
  return expectedIdHex;
}
