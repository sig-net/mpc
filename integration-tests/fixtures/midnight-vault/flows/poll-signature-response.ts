// `pollSignatureResponse` — stage 1 of the MPC round trip: poll the central
// signet contract's emitted signature response events by request id until the
// MPC's ECDSA signature over a request's EVM transaction appears, verifying
// every post on the way. There is deliberately no push/websocket alternative.
import { type RequestIdHex, signBidirectionalEventToSignedEvmTransaction } from "@sig-net/midnight";
import type { Transaction } from "ethers";

import { PollProgress } from "./poll-progress.ts";
import { sleepUnlessAborted } from "./sleep-unless-aborted.ts";
import { createResponseReader, type VaultContext } from "./vault-context.ts";

/** Options for {@link pollSignatureResponse}. */
export interface PollSignatureResponseOptions {
  /** The request id to poll for. */
  readonly requestId: RequestIdHex;
  /** Poll interval in milliseconds. */
  readonly intervalMs: number;
  /** Give-up timeout in milliseconds. */
  readonly timeoutMs: number;
  /**
   * EVM address the MPC's signature must recover to — the request's derived
   * sender. Deposit requests are signed by the user's derived account
   * (`context.evmUserAddress`); withdraw requests by the VAULT's
   * (`context.evmVaultAddress`). Always explicit: this flow is generic over
   * request kinds, and which account signs is the caller's knowledge.
   */
  readonly expectedSigner: string;
  /**
   * The resolved ledger-tree path of the request map. Defaults to
   * VAULT_REQUESTS_PATH ([0, 0], the signBidirectionalEventMap the approves and
   * withdraw share); deposits pass VAULT_DEPOSIT_REQUESTS_PATH ([1, 3], the
   * depositEventMap), swaps VAULT_SWAP_REQUESTS_PATH ([1, 7], the swapEventMap),
   * supply and redeem their own maps' exported paths, since each of those
   * requests is registered in its separate map.
   */
  readonly requestsPath?: readonly number[];
}

/**
 * Poll the signet contract until a VALID signature response for
 * `options.requestId` appears among its emitted response events, then
 * reconstruct and return the fully signed EVM transaction as a typed ethers
 * {@link Transaction}, ready to hand straight to `broadcastEvm`. Serialize
 * it (`.serialized`) only at the edge — for stdout or
 * `eth_sendRawTransaction`.
 *
 * Enumeration and verification are delegated to signet-midnight's
 * `SignetRequestResponseReader`: each tick reads the response events declared
 * under `requestId` and, the event log being unauthenticated, judges every
 * post by whether its signature recovers to the request's MPC-derived sender
 * (see {@link PollSignatureResponseOptions.expectedSigner}) over the requested
 * transaction's signing hash. The first valid post wins. The signed
 * transaction is assembled from the request record and that response via
 * {@link signBidirectionalEventToSignedEvmTransaction}. This flow owns
 * the poll loop, the timeout, and the reporting: each rejected post is
 * warned once across the loop's lifetime, not every tick. For the MPC's
 * respond-bidirectional response of the EVM result, see
 * `pollRespondBidirectional`.
 *
 * @param context - The flow context.
 * @param options - What to poll for and how patiently.
 * @returns The broadcast-ready signed EVM transaction.
 * @throws {Error} When a contract has no state on-chain, the request is not on
 *   the vault's ledger, or `timeoutMs` elapses with no valid response posted.
 */
export async function pollSignatureResponse(
  context: VaultContext,
  options: PollSignatureResponseOptions,
): Promise<Transaction> {
  console.log(`signet contract:   ${context.signetContractAddress}`);
  console.log(`request id:         ${options.requestId}`);
  console.log(`expected signer:    ${options.expectedSigner}`);
  console.log(
    `poll:               every ${String(options.intervalMs)}ms, up to ${String(options.timeoutMs)}ms`,
  );

  const reader = createResponseReader(context, options.requestsPath);

  // The reader is single-shot; this loop owns the cadence and the give-up
  // timeout. Rejected posts are immutable emitted events, so warn each post
  // index once across the loop's lifetime, not every tick.
  const progress = new PollProgress(`signature ${options.requestId}`, options.timeoutMs);
  const rejected = new Map<bigint, string>();
  const giveUp = new AbortController();
  const timer = setTimeout(() => {
    giveUp.abort();
  }, options.timeoutMs);
  try {
    while (!giveUp.signal.aborted) {
      const { verified, verdicts } = await reader.getVerifiedSignatureRespondedEvent(
        options.requestId,
        options.expectedSigner,
      );
      for (const verdict of verdicts) {
        if (verdict.rejectedReason !== undefined) {
          const reason = `${verdict.rejectedReason}${verdict.signer === undefined ? "" : `. Expected ${options.expectedSigner}, recovered ${verdict.signer}`}`;
          rejected.set(verdict.index, reason);
          progress.failure(
            String(verdict.index),
            `response post ${String(verdict.index)} rejected: ${reason}`,
          );
        }
      }
      progress.update(
        `${String(verdicts.length)} posts observed, ${String(rejected.size)} rejected posts`,
      );
      if (verified !== undefined) {
        const validIndex = verdicts.find((verdict) => verdict.rejectedReason === undefined)?.index;
        console.log(`valid response found (post ${String(validIndex ?? "unknown")})`);
        // Reconstruct the broadcast-ready signed transaction from the request
        // record and this response. The reader's request fetch is cached (its
        // verification already fetched it), so this adds no extra query.
        const request = await reader.getSignatureRequest(options.requestId);
        return signBidirectionalEventToSignedEvmTransaction(request, verified);
      }
      await sleepUnlessAborted(options.intervalMs, giveUp.signal);
    }
    throw new Error(
      `timed out: ${progress.summary()}. Rejections: ${[...rejected].map(([index, reason]) => `${String(index)}: ${reason}`).join(" | ") || "none"}`,
    );
  } finally {
    clearTimeout(timer);
  }
}
