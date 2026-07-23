/**
 * The failure vocabulary. Every non-200 is `{"code":"…","message":"…"}`.
 *
 * The caller has to branch on failures, and the only other signal is prose
 * written for humans and rewritten for humans. The code is the stable half of
 * the answer; a message may be reworded in any release, a code may not.
 */

/**
 * Split by what the caller should DO, which is why several codes share a status:
 * a 409 that is `state_conflict` should be retried as-is, a 409 that is
 * `contract_mismatch` never will succeed until this service is redeployed.
 */
export type ErrorCode =
  /** Malformed envelope, bad hex, failed validation. Fix the request. */
  | "bad_request"
  /** Body over the seam's cap. Split the batch. */
  | "payload_too_large"
  | "not_found"
  /** The ledger refused bytes the CALLER supplied: wrong blob, or another ledger line. */
  | "decode_failed"
  /** Bytes read from the CHAIN carry a tag this build does not speak. See `GET /health`. */
  | "ledger_mismatch"
  /** Wrong address, or not deployed yet. */
  | "contract_absent"
  /** Deployed verifier keys differ from this build's. Redeploy or repoint `MIDNIGHT_PUB_MANAGED_DIR`. */
  | "contract_mismatch"
  /**
   * Another post won the race for this request id. Retryable as-is: the loser
   * never entered a block and paid no fee. BEST-EFFORT — see `RESPOND_STAGES`;
   * a submit failure that cannot be identified answers `submit_rejected`.
   */
  | "state_conflict"
  | "node_unavailable"
  | "prove_failed"
  /** No spendable dust right now. One wallet sustains roughly one post per 35 seconds. */
  | "wallet_unfunded"
  /** Balancing failed for a reason other than funds. */
  | "balance_failed"
  | "submit_rejected"
  /** Unclassified. The message is the only detail. */
  | "internal";

/** The code is the contract; the status is the courtesy. */
const STATUS: Readonly<Record<ErrorCode, number>> = {
  bad_request: 400,
  payload_too_large: 413,
  not_found: 404,
  decode_failed: 422,
  ledger_mismatch: 502,
  contract_absent: 409,
  contract_mismatch: 409,
  state_conflict: 409,
  node_unavailable: 502,
  prove_failed: 502,
  wallet_unfunded: 503,
  balance_failed: 502,
  submit_rejected: 502,
  internal: 500,
};

/** A failure that already knows its own code: everywhere the cause is known at the throw site. */
export class PublisherError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "PublisherError";
  }
}

export function badRequest(message: string): PublisherError {
  return new PublisherError("bad_request", message);
}

export function statusFor(code: ErrorCode): number {
  return STATUS[code];
}

export function errorBody(code: ErrorCode, message: string): string {
  return JSON.stringify({ code, message });
}

/**
 * One stage of `POST /respond`. The stage supplies the code structurally, and
 * `refine` sharpens it where a measured substring identifies a cause worth
 * acting on differently. Patterns match against `describeFailure`'s rendering,
 * which includes the error class names Effect hides in `name`.
 */
export interface RespondStage {
  readonly fallback: ErrorCode;
  readonly refine: readonly (readonly [pattern: string, code: ErrorCode])[];
}

/**
 * THE ONLY PLACE THIS SERVICE MATCHES ON A DEPENDENCY'S ERROR TEXT, pinned by
 * `tests/errors.test.ts` against errors built through a real `Effect.runPromise`
 * rejection rather than hand-set `.name`s. A pattern that stops matching
 * degrades the answer by one step (`wallet_unfunded` becomes `balance_failed`)
 * rather than losing it, because the stage itself needs no matching.
 *
 * The two entries have DIFFERENT provenance and the difference matters:
 *
 * - `Wallet.InsufficientFunds` is confirmed reachable. `Data.TaggedError` puts
 *   the tag in `name` and `DustWallet` runs its Effect with no outer wrapper, so
 *   it survives into `describeFailure`. Verified against the installed source.
 * - `ReadMismatch` is NOT confirmed. `submissionService` flattens every node
 *   error into `SubmissionError{message:'Transaction submission error'}`, so it
 *   can only ever appear in the nested cause, which is why `inStage` matches
 *   against the rendered chain and not just the message. Whether the node client
 *   surfaces the ledger's text at all is unverified, and
 *   `PolkadotNodeClient`'s hardcoded invalid-transaction message suggests it may
 *   not. Treat `state_conflict` as best-effort until a live same-id race
 *   confirms it; the fallback `submit_rejected` is always correct.
 */
export const RESPOND_STAGES = {
  read: { fallback: "node_unavailable", refine: [] },
  prove: { fallback: "prove_failed", refine: [] },
  balance: {
    fallback: "balance_failed",
    refine: [
      ["Wallet.InsufficientFunds", "wallet_unfunded"],
      ["could not balance dust", "wallet_unfunded"],
    ],
  },
  submit: { fallback: "submit_rejected", refine: [["ReadMismatch", "state_conflict"]] },
} as const satisfies Record<string, RespondStage>;

export function classify(stage: RespondStage, described: string): ErrorCode {
  return stage.refine.find(([pattern]) => described.includes(pattern))?.[1] ?? stage.fallback;
}
