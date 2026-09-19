// `startDeposit`: record a deposit SignBidirectionalEvent in the vault's depositEventMap. It
// asks the MPC to sign an EVM `transfer(vault, amount)` on the ERC20, sent from the user's
// derived address. The request id is recomputed off-chain with the library's TS twin of the
// request-id circuit and asserted against the ledger map key before it is returned. The
// settle side lives in complete-deposit.ts.
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

/** Options for {@link startDeposit}. */
export interface StartDepositOptions {
  /** Deposit amount in ERC20 base units. */
  readonly amount: bigint;
  /** Nonce of the user's derived EVM account (the sweep tx sender). */
  readonly evmNonce: bigint;
  /**
   * The ERC20 to deposit; defaults to the suite's `ERC20_ADDRESS`. The vault mints a distinct
   * colour per token (`vaultTokenType(erc20Address, …)`), so the Aave leg deposits its own
   * underlying (Aave USDC) while the swap/withdraw legs keep the default.
   */
  readonly erc20Address?: string;
}

/**
 * Call the vault's `startDeposit` circuit on the deployed contract and return
 * the resulting request id.
 *
 * The circuit takes only what the caller genuinely chooses: their derived
 * account's nonce, the gas envelope (this flow uses the shared
 * `ERC20_TRANSFER_*` defaults, and the caller's account pays), the MPC key
 * version, and the deposit itself. Everything else (chain, calldata, routing,
 * and even the derivation path, which is the caller's identity commitment
 * recomputed in-circuit) is contract-composed from the initialise-pinned
 * config. The expected event record is reconstructed off-chain (chain fields
 * read from the ledger, routing from the {@link VAULT_MPC_ROUTING} mirror),
 * its id computed with the library's `calculateRequestId` TS twin, and
 * asserted present as a ledger map key after the call.
 *
 * @param context - The flow context.
 * @param options - The deposit arguments.
 * @returns The request id as 64-char lowercase hex.
 * @throws {Error} If an option is invalid, the vault is uninitialised, or the
 *   recomputed id does not appear on the ledger.
 */
export async function startDeposit(
  context: VaultContext,
  options: StartDepositOptions,
): Promise<RequestIdHex> {
  if (options.amount <= 0n) {
    throw new Error(`amount must be a positive integer; got ${String(options.amount)}.`);
  }
  if (options.evmNonce < 0n) {
    throw new Error(`evmNonce must be non-negative; got ${String(options.evmNonce)}.`);
  }
  const erc20Address = options.erc20Address ?? context.erc20Address;
  const erc20 = evmAddressBytes(erc20Address);
  console.log(`vault contract:    ${context.vaultContractAddress}`);
  console.log(`erc20:             ${erc20Address}`);

  console.log(`caller commitment: ${context.identity.commitmentHex}`);

  // Pre-call ledger read: the request nonce the contract will use, the sealed
  // vault EVM address its calldata will pay to, and the pinned chain config.
  await logTokenAmount(
    context.evmRpcUrl,
    erc20Address,
    context.evmUserAddress,
    options.amount,
    "start-deposit amount",
  );
  const before = await readVaultLedger(
    context.providers.publicDataProvider,
    context.vaultContractAddress,
  );
  if (!before.initialised) {
    throw new Error("vault is not initialised, run the initialise flow first");
  }
  const requestNonce = before.signetRequestNonce;
  const vaultEvmAddress = before.vaultEvmAddress;

  const gasLimit = ERC20_TRANSFER_GAS_LIMIT;
  const maxFeePerGas = ERC20_TRANSFER_MAX_FEE_PER_GAS;
  const maxPriorityFeePerGas = ERC20_TRANSFER_MAX_PRIORITY_FEE_PER_GAS;
  const keyVersion = SIGNET_DEFAULT_KEY_VERSION;

  // The record the contract will store, reconstructed byte for byte: the
  // event's own sender (the vault contract, kernel.self() in-circuit), the
  // contract-composed envelope on the initialise-pinned chain, the
  // contract-built `transfer(vaultEvmAddress, amount)` calldata (the raw
  // selector, the ABI-ready big-endian address and amount words, as broadcast), the
  // caller's identity commitment as the 32-byte derivation path, and the
  // contract-fixed routing.
  const expectedRecord: SignBidirectionalEvent = {
    sender: { bytes: hexToBytes(stripHexPrefix(context.vaultContractAddress)) },
    requestNonce,
    keyVersion,
    path: context.identity.commitment,
    ...VAULT_MPC_ROUTING,
    txParamType: TxParamType.evmType2,
    txParams: {
      to: erc20,
      chainId: before.evmChainId,
      nonce: options.evmNonce,
      gasLimit,
      maxFeePerGas,
      maxPriorityFeePerGas,
      value: 0n,
      accessListEntryCount: 0n,
      accessList: [],
      calldata: {
        is_some: true,
        value: {
          selector: ERC20_TRANSFER_SELECTOR,
          noWords: 2n,
          words: [evmAddressAbiWord(vaultEvmAddress), numericAbiWord(options.amount)],
        },
      },
    },
  };
  const expectedIdHex = requestIdHex(calculateRequestId(expectedRecord));
  logEvmFeeCap(
    expectedIdHex,
    context.evmUserAddress,
    expectedRecord.txParams.gasLimit,
    expectedRecord.txParams.maxFeePerGas,
    expectedRecord.txParams.maxPriorityFeePerGas,
  );

  const result = await context.vault.callTx.startDeposit(
    options.evmNonce,
    gasLimit,
    maxFeePerGas,
    maxPriorityFeePerGas,
    keyVersion,
    {
      erc20Address: erc20,
      amount: options.amount,
    },
  );
  console.log(`deposit finalized in tx ${result.public.txId}`);

  // The depositEventMap key IS the record's transientHash digest: recomputing
  // it off-chain and finding it on the ledger proves both sides agree on every
  // byte of the event.
  const after = await readVaultLedger(
    context.providers.publicDataProvider,
    context.vaultContractAddress,
  );
  const index = toSignBidirectionalEventIndex(after.depositEventMap);
  if (!index.has(expectedIdHex)) {
    throw new Error(
      `recomputed request id ${expectedIdHex} not found in the vault's deposit map ` +
        `(present ids: [${[...index.keys()].join(", ")}], was another request submitted concurrently?)`,
    );
  }
  console.log(`request id:        ${expectedIdHex}`);
  return expectedIdHex;
}
