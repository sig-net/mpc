// `broadcastEvm`: send an MPC-signed EVM transaction to the EVM chain. The
// MPC only SIGNS; broadcasting is a thin client responsibility.

import {
  formatEther,
  formatUnits,
  JsonRpcProvider,
  type Transaction,
  type TransactionReceipt,
} from "ethers";

import type { VaultContext } from "./vault-context.ts";

/** Options for {@link broadcastEvm}. */
export interface BroadcastEvmOptions {
  /** The signed EVM transaction to broadcast (e.g. from `pollSignatureResponse`). */
  readonly transaction: Transaction;
  /**
   * When true, a mined-but-reverted tx (`status 0`) is RETURNED instead of throwing. Swaps
   * set this: an on-chain revert (slippage / liquidity) is a valid outcome the MPC attests
   * as a failure and the refund path settles: not an error. Defaults to false (deposit /
   * withdraw treat a revert as fatal, letting the caller decide).
   */
  readonly tolerateRevert?: boolean;
}

// A thrown value's `code`, when it actually carries one as a string. Narrows
// from `unknown` rather than asserting a shape nothing checked.
function errorCode(err: unknown): string | undefined {
  if (typeof err === "object" && err !== null && "code" in err && typeof err.code === "string") {
    return err.code;
  }
  return undefined;
}

/**
 * The "this exact tx was already submitted" family of node errors. Re-POSTing a
 * signed tx the node has already seen is a no-op on-chain (same nonce+signature
 * ⇒ same hash ⇒ one transaction), so these are safe to swallow and fall through
 * to waiting on the hash. Distinct from a *reverted* tx, which mines and gets a
 * receipt with `status: 0`.
 *
 * @param err - The value the broadcast attempt threw.
 * @returns Whether the node is reporting this exact transaction as already seen.
 */
function isAlreadySubmitted(err: unknown): boolean {
  // ethers surfaces "nonce too low" as NONCE_EXPIRED; "already known" /
  // "already imported" / "txpool is full"-style dupes come through as the raw
  // node message, so match on text too.
  if (errorCode(err) === "NONCE_EXPIRED") return true;
  const rawMessage =
    typeof err === "object" && err !== null && "message" in err && typeof err.message === "string"
      ? err.message
      : "";
  const message = rawMessage.toLowerCase();
  return (
    message.includes("already known") ||
    message.includes("already imported") ||
    message.includes("alreadyknown") ||
    message.includes("nonce too low")
  );
}

/**
 * Broadcast a signed EVM transaction to the context's EVM chain and wait for
 * one confirmation. **Idempotent**: safe to call repeatedly with the same
 * signed transaction.
 *
 * A signed EVM tx is content-addressed: its hash is a pure function of its
 * bytes (nonce + fields + signature): so the protocol guarantees it can only
 * ever mine once. This function leans on that: it derives the hash locally,
 * short-circuits if the tx has already mined (whether it succeeded OR reverted),
 * and tolerates the node reporting the tx as already-submitted on a re-run.
 *
 * The one case it cannot make idempotent is a *burned nonce*: if the account's
 * nonce has advanced past this tx but this tx never mined, some other
 * transaction took the slot and this one can never land. That is surfaced as an
 * error rather than hung on.
 *
 * @param context - The flow context.
 * @param options - The transaction to broadcast.
 * @returns The mined transaction's receipt (its `hash` is the tx hash the
 *   MPC traces the execution output from).
 * @throws {Error} When the transaction reverted on-chain, or its nonce was
 *   consumed by a different transaction (so it can never mine).
 */
export async function broadcastEvm(
  context: VaultContext,
  options: BroadcastEvmOptions,
): Promise<TransactionReceipt> {
  const provider = new JsonRpcProvider(context.evmRpcUrl);
  const started: number = Date.now();
  const maximumFee: bigint =
    options.transaction.gasLimit *
    (options.transaction.maxFeePerGas ?? options.transaction.gasPrice ?? 0n);
  try {
    const tolerateRevert = options.tolerateRevert ?? false;

    // The hash and sender are already borne by the signed transaction: no
    // parsing or network needed. They are only null if the tx is unsigned.
    const { hash, from, nonce } = options.transaction;
    if (hash === null || from === null) {
      throw new Error("transaction is missing a signature (cannot derive hash/sender)");
    }

    console.log(`evm rpc:   ${context.evmRpcUrl}`);
    console.log(`tx hash:   ${hash} (nonce ${String(nonce)})`);

    // 1. Already mined? A receipt exists whether the tx succeeded OR reverted —
    //    both consume the nonce, so there is nothing left to broadcast either way.
    const mined = await provider.getTransactionReceipt(hash);
    if (mined !== null) {
      console.log(`already mined at block ${String(mined.blockNumber)}`);
      return assertMinedOk(mined, hash, tolerateRevert, maximumFee);
    }

    // 2. Broadcast. If the node has already seen this exact tx, that's a no-op —
    //    swallow it and fall through to waiting on the hash.
    try {
      await provider.broadcastTransaction(options.transaction.serialized);
      console.log(`broadcast: ${hash}: waiting for 1 confirmation…`);
    } catch (err) {
      if (!isAlreadySubmitted(err)) throw err;
      console.log(`already submitted: waiting for 1 confirmation…`);
    }

    // 3. Wait for OUR hash to confirm, but bail if the account nonce advances past
    //    this tx without it mining: that means a *different* tx took the slot and
    //    this one can never land, so waiting on the hash would hang forever.
    for (;;) {
      let receipt: TransactionReceipt | null;
      try {
        receipt = await provider.waitForTransaction(hash, 1, 15_000);
      } catch (err) {
        // ethers v6 REJECTS with a TIMEOUT error when the wait window elapses (it
        // does NOT resolve to null): a confirmation slower than the window is
        // normal on a live chain, so treat it as "not yet" and fall through to
        // the burned-nonce check below, then keep waiting. Any other error is real.
        if (errorCode(err) !== "TIMEOUT") throw err;
        receipt = null;
      }
      if (receipt !== null) {
        console.log(`confirmed: ${hash}`);
        return assertMinedOk(receipt, hash, tolerateRevert, maximumFee);
      }
      const latestNonce = await provider.getTransactionCount(from, "latest");
      if (latestNonce > nonce) {
        // The nonce advanced: either OUR tx just mined (waitForTransaction can
        // miss an inclusion that lands right at its window edge) or a different
        // tx took the slot. Only the receipt distinguishes the two.
        const latestReceipt = await provider.getTransactionReceipt(hash);
        if (latestReceipt !== null) {
          console.log(`confirmed: ${hash}`);
          return assertMinedOk(latestReceipt, hash, tolerateRevert, maximumFee);
        }
        throw new Error(
          `nonce ${String(nonce)} for ${from} was consumed by a different transaction . ` +
            `this signed tx (${hash}) can never mine`,
        );
      }
      console.log(
        `${hash}: pending, account nonce ${String(latestNonce)}, ${((Date.now() - started) / 1000).toFixed(1)}s elapsed`,
      );
    }
  } finally {
    provider.destroy();
  }
}

/**
 * A mined receipt with `status: 0` means the tx was included but its execution
 * reverted (nonce consumed, gas burned, state rolled back). Treat that as a
 * failure rather than silently returning the receipt of a reverted tx: unless
 * `tolerateRevert` (a swap, whose revert the refund path settles).
 *
 * @param receipt - The mined receipt to check.
 * @param hash - The transaction hash, for the error message.
 * @param tolerateRevert - When true, a reverted receipt is returned instead of throwing.
 * @param maximumFee - Maximum gas fee of the signed transaction in wei.
 * @returns The same receipt, when the transaction succeeded (or `tolerateRevert`).
 * @throws {Error} If the receipt reports `status: 0` and `tolerateRevert` is false.
 */
function assertMinedOk(
  receipt: TransactionReceipt,
  hash: string,
  tolerateRevert: boolean,
  maximumFee: bigint,
): TransactionReceipt {
  console.log(formatEvmReceipt(receipt, maximumFee));
  if (receipt.status === 0 && !tolerateRevert) {
    throw new Error(
      `transaction ${hash} reverted on-chain (mined in block ${String(receipt.blockNumber)}, status 0)`,
    );
  }
  return receipt;
}

/**
 * Format the mined result and its actual gas fee alongside the signed maximum.
 *
 * @param receipt - Mined transaction receipt.
 * @param maximumFee - Signed maximum gas fee in wei.
 * @returns Receipt status and gas accounting in explicit units.
 */
export function formatEvmReceipt(
  receipt: Pick<
    TransactionReceipt,
    "hash" | "status" | "blockNumber" | "gasUsed" | "gasPrice" | "fee"
  >,
  maximumFee: bigint,
): string {
  return `${receipt.hash}: ${receipt.status === 1 ? "succeeded" : receipt.status === 0 ? "reverted" : "status unavailable"}, block ${String(receipt.blockNumber)}, gas used ${String(receipt.gasUsed)}, effective gas price ${formatUnits(receipt.gasPrice, "gwei")} gwei, actual gas fee ${formatEther(receipt.fee)} ETH, signed maximum gas fee ${formatEther(maximumFee)} ETH`;
}
