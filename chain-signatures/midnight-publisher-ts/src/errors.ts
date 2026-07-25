/**
 * Every non-200 is `{"code","message"}` and, when a dependency's rendered cause
 * chain says more than its one-line message, a `detail` carrying that chain.
 * The code is the stable half a caller branches on and names where the request
 * died on its own; message and detail are evidence, reworded freely.
 */

/**
 * An HTTP status and an already-serialized body. `fatal` marks the LAST reply
 * this process will send: the server stops once it is flushed.
 */
export type Reply = { readonly status: number; readonly body: string; readonly fatal?: true };

/** Split by what the caller should DO, which is why several share a status. */
export type ErrorCode =
  /** Malformed envelope, bad hex, failed validation. Fix the request. */
  | "bad_request"
  | "not_found"
  /** The ledger refused bytes the CALLER supplied: wrong blob, or another ledger line. */
  | "decode_failed"
  /** Bytes read from the CHAIN carry a tag this build does not speak. See `GET /health`. */
  | "ledger_mismatch"
  /** Wrong address, or not deployed yet. */
  | "contract_absent"
  /** Deployed verifier keys differ from this build's. Redeploy or repoint `MIDNIGHT_PUB_MANAGED_DIR`. */
  | "contract_mismatch"
  /** Another post won the race. Retryable as-is: the loser paid no fee. Best-effort; see `LOST_THE_RACE`. */
  | "state_conflict"
  | "node_unavailable"
  | "prove_failed"
  /** No spendable dust right now. One wallet sustains roughly one post per 35 seconds. */
  | "wallet_unfunded"
  /** The funding wallet could not sync within the boot deadline. Check the indexer, then retry. */
  | "wallet_unsynced"
  /** Another respond currently holds the one dust UTXO. Retry when it answers, ~35s. */
  | "wallet_busy"
  /** Balancing failed for a reason other than funds. */
  | "balance_failed"
  | "submit_rejected"
  /** Unclassified. The message is the only detail. */
  | "internal";

export const STATUS: Readonly<Record<ErrorCode, number>> = {
  bad_request: 400,
  not_found: 404,
  decode_failed: 422,
  ledger_mismatch: 502,
  contract_absent: 409,
  contract_mismatch: 409,
  state_conflict: 409,
  node_unavailable: 502,
  prove_failed: 502,
  wallet_unfunded: 503,
  wallet_unsynced: 503,
  wallet_busy: 503,
  balance_failed: 502,
  submit_rejected: 502,
  internal: 500,
};

/** Thrown wherever the cause is known at the throw site. */
export class PublisherError extends Error {
  constructor(readonly code: ErrorCode, message: string, readonly detail?: string) {
    super(message);
    this.name = "PublisherError";
  }
}

/** A substring that sharpens a step's default code into one the caller acts on differently. */
export type Refinement = readonly [pattern: string, code: ErrorCode];

/**
 * The single funnel, so status and body cannot disagree. `logLabel` omitted
 * means silent; a `bad_request` is the caller's own mistake.
 */
export function fail(code: ErrorCode, message: string, logLabel?: string, detail?: string): Reply {
  if (logLabel !== undefined && code !== "bad_request") {
    console.error(`${logLabel} [${code}]: ${message}${detail === undefined ? "" : `\n${detail}`}`);
  }
  const body = { code, message, ...(detail === undefined ? {} : { detail }) };
  return { status: STATUS[code], body: JSON.stringify(body) };
}

/** The `invalid JSON:` preamble both seams answer with, byte for byte. */
export function jsonObject(body: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (error) {
    throw new PublisherError("bad_request", `invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new PublisherError("bad_request", "invalid JSON: expected a JSON object");
  }
  return parsed as Record<string, unknown>;
}
