/**
 * Every non-200 is `{"code","message"}`, and nothing else. The code is the stable
 * half a caller branches on, and it names where the request died on its own; the
 * message is evidence, reworded freely. A dependency's rendered cause chain goes
 * to the LOG, never the wire — see {@link fail}.
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
  /** The funding wallet could not open or sync. Check the indexer, then retry. */
  | "wallet_unsynced"
  /** Another respond currently holds the one dust UTXO. Retry when it answers, ~35s. */
  | "wallet_busy"
  /** Balancing failed for a reason other than funds. */
  | "balance_failed"
  | "submit_rejected"
  /** Unclassified: the message is all there is, and the log has the rest. */
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

/** Thrown wherever the cause is known at the throw site; `options.cause` carries whatever it wrapped. */
export class PublisherError extends Error {
  constructor(readonly code: ErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "PublisherError";
  }
}

function describeOne(value: unknown): string {
  if (value instanceof Error) {
    return [value.name === "Error" ? "" : value.name, value.message].filter(Boolean).join(": ");
  }
  if (typeof value !== "object" || value === null) return String(value);
  const { _tag, message } = value as { _tag?: unknown; message?: unknown };
  const named = [_tag, message].filter((part) => typeof part === "string" && part.length > 0).join(": ");
  if (named.length > 0) return named;
  try {
    // Anything else: better an object literal than `[object Object]`.
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

/**
 * One line that NAMES a thrown value, causes innermost last. `message` alone is
 * not enough: Effect's `FiberFailure` keeps the failing class in `name`, and
 * `midnight-js-contracts` rewraps with `new Error(msg, { cause })`.
 */
export function describeFailure(error: unknown): string {
  const parts: string[] = [];
  // Bounded, so a self-referential `cause` chain terminates rather than hangs.
  for (let current: unknown = error, depth = 0; current !== undefined && current !== null && depth < 8; depth += 1) {
    const text = describeOne(current);
    // A wrapper usually quotes what it wrapped; do not say it twice.
    if (text.length > 0 && !parts.some((part) => part.includes(text))) parts.push(text);
    current = typeof current === "object" ? (current as { cause?: unknown }).cause : undefined;
  }
  return parts.join(": ") || String(error);
}

/**
 * The single funnel, so status and body cannot disagree. `logLabel` omitted means
 * silent; a `bad_request` is the caller's own mistake. `evidence` is LOG-ONLY:
 * `String` renders Effect's whole cause chain, which an operator wants and a
 * caller branching on `code` does not.
 */
export function fail(code: ErrorCode, message: string, logLabel?: string, evidence?: unknown): Reply {
  if (logLabel !== undefined && code !== "bad_request") {
    console.error(`${logLabel} [${code}]: ${String(evidence ?? message).slice(0, 4_000)}`);
  }
  return { status: STATUS[code], body: JSON.stringify({ code, message }) };
}

/** Any thrown value as its answer: a {@link PublisherError} names itself, anything else is `unclassified`. */
export function replyTo(error: unknown, logLabel: string, unclassified: ErrorCode = "internal"): Reply {
  const named = error instanceof PublisherError;
  const evidence = named && error.cause !== undefined ? error.cause : error;
  return fail(named ? error.code : unclassified, named ? error.message : describeFailure(error), logLabel, evidence);
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
