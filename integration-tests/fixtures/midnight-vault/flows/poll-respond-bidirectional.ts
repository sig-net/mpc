// `pollRespondBidirectional`: stage 2 of the MPC round trip. Poll the Signet
// singleton's emitted respond-bidirectional events by request id until an MPC
// attestation appears whose signature VERIFIES over the independently
// recomputed serialized output for the request, and return the resolved
// outcome. There is deliberately no push/websocket alternative.
import type { RequestIdHex } from "@sig-net/midnight";

import { PollProgress } from "./poll-progress.ts";
import { sleepUnlessAborted } from "./sleep-unless-aborted.ts";
import type { VaultContext } from "./vault-context.ts";
import { fetchAttestedRespondOutcome, type RespondOutcome } from "./respond-output.ts";

export { fetchAttestedRespondOutcome, type RespondOutcome } from "./respond-output.ts";

/** Options for {@link pollRespondBidirectional}. */
export interface PollRespondBidirectionalOptions {
  /** The request id to poll for. */
  readonly requestId: RequestIdHex;
  /** Poll interval in milliseconds. */
  readonly intervalMs: number;
  /** Give-up timeout in milliseconds. */
  readonly timeoutMs: number;
  /**
   * The resolved ledger-tree path of the map holding the request. Deposits
   * pass VAULT_DEPOSIT_REQUESTS_PATH (the depositEventMap); withdrawals take
   * the default VAULT_REQUESTS_PATH (the signBidirectionalEventMap they share
   * with the approves).
   */
  readonly requestsPath?: readonly number[];
}

/**
 * Poll the signet contract until an MPC respond-bidirectional attestation
 * for `options.requestId` VERIFIES over the independently recomputed output,
 * and return the resolved outcome.
 *
 * The event carries only the MPC's signature, so each tick recomputes the
 * serialized output from the observed raw EVM output and checks the
 * posted events' signatures against it (see `fetchAttestedRespondOutcome`):
 * the event log is unauthenticated, and that check is what makes a returned
 * record meaningful off-chain. The settle circuits run the same check
 * in-circuit, which is the actual authentication gate. This flow owns the poll loop, the timeout,
 * and the reporting: it logs the outcome (success flag / MPC failure
 * output); acting on it (claiming, refunding) is the caller's job.
 *
 * @param context - The flow context.
 * @param options - What to poll for and how patiently.
 * @returns The resolved outcome (attested event + verified output bytes).
 * @throws {Error} When the contract has no state on-chain, or `timeoutMs`
 *   elapses with no verifying attestation posted (an EVM endpoint that
 *   stays unreachable surfaces as this timeout: each tick's trace failure
 *   is logged and retried, this loop owns the deadline).
 */
export async function pollRespondBidirectional(
  context: VaultContext,
  options: PollRespondBidirectionalOptions,
): Promise<RespondOutcome> {
  console.log(`signet contract:   ${context.signetContractAddress}`);
  console.log(`request id:        ${options.requestId}`);
  console.log(
    `poll:              every ${String(options.intervalMs)}ms, up to ${String(options.timeoutMs)}ms`,
  );

  // The reads are single-shot; this loop owns the cadence and the give-up
  // timeout.
  const progress = new PollProgress(`attestation ${options.requestId}`, options.timeoutMs);
  const giveUp = new AbortController();
  const timer = setTimeout(() => {
    giveUp.abort();
  }, options.timeoutMs);
  try {
    while (!giveUp.signal.aborted) {
      const outcome = await fetchAttestedRespondOutcome(
        context,
        options.requestId,
        options.requestsPath,
        progress,
      );
      if (outcome !== undefined) {
        if (outcome.matchedFailureOutput) {
          console.log("remote execution FAILED (MPC failure output attested)");
        } else {
          console.log(`remote execution ${outcome.succeeded ? "succeeded" : "returned false"}`);
        }
        return outcome;
      }
      await sleepUnlessAborted(options.intervalMs, giveUp.signal);
    }
    throw new Error(`timed out: ${progress.summary()}`);
  } finally {
    clearTimeout(timer);
  }
}
