/**
 * Every non-200 is `{"code","message"}` plus, on the respond path, the `stage`
 * that failed (`boot|read|prove|balance|submit`). The code and stage are the
 * stable halves a caller branches on; the message is prose and may be reworded
 * in any release.
 */

import { redact } from "./config.js";

/** An HTTP status and an already-serialized body. */
export type Reply = { readonly status: number; readonly body: string };

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
  /** Another post won the race. Retryable as-is: the loser paid no fee. Best-effort, see `RESPOND_STAGES`. */
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

const STATUS: Readonly<Record<ErrorCode, number>> = {
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
  constructor(readonly code: ErrorCode, message: string, readonly stage?: string) {
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

/**
 * The stage supplies the code structurally; `refine` sharpens it where a
 * measured substring names a cause worth acting on differently.
 */
type Refinement = readonly [pattern: string, code: ErrorCode];
export type RespondStage = { readonly name: string; readonly fallback: ErrorCode; readonly refine: readonly Refinement[] };

/**
 * The only place this service matches on a dependency's error text, pinned by
 * `tests/errors.test.ts`. A pattern that stops matching degrades one step to the
 * stage fallback rather than losing the answer.
 *
 * `Wallet.InsufficientFunds` is confirmed reachable. `ReadMismatch` is not:
 * `submissionService` flattens every node error into a constant message, so it
 * can only appear in the nested cause, and whether the node client surfaces it
 * at all is unverified.
 */
export const RESPOND_STAGES = {
  read: { name: "read", fallback: "node_unavailable", refine: [] },
  prove: { name: "prove", fallback: "prove_failed", refine: [] },
  balance: { name: "balance", fallback: "balance_failed", refine: [["Wallet.InsufficientFunds", "wallet_unfunded"], ["could not balance dust", "wallet_unfunded"]] },
  submit: { name: "submit", fallback: "submit_rejected", refine: [["ReadMismatch", "state_conflict"]] },
} as const satisfies Record<string, RespondStage>;

export function classify(stage: RespondStage, described: string): ErrorCode {
  return stage.refine.find(([pattern]) => described.includes(pattern))?.[1] ?? stage.fallback;
}

/**
 * Built from the code, so status and body cannot disagree. Module-private on
 * purpose: `failRedacted` is the only exported way to build an error reply, so
 * nothing can answer the caller without passing through redaction first.
 */
function fail(code: ErrorCode, message: string, stage?: string): Reply {
  return { status: statusFor(code), body: JSON.stringify(stage === undefined ? { code, message } : { code, message, stage }) };
}

/**
 * The single funnel every error answer passes through, so the funding seed
 * cannot reach a response body or a log line without going through `redact`
 * first. Classification stays at the throw site; this owns only the
 * redact-log-serialize tail. Keep every error path routed through here and the
 * redaction stays total by construction rather than by remembering to add it.
 *
 * `logLabel` omitted means silent: a `bad_request` is the caller's own request
 * coming back at it, not this service failing, and is never worth a log line.
 */
export function failRedacted(code: ErrorCode, rawMessage: string, secrets: readonly string[], logLabel?: string, stage?: string): Reply {
  const message = redact(rawMessage, secrets);
  if (logLabel !== undefined && code !== "bad_request") console.error(`${logLabel} [${code}${stage === undefined ? "" : ` @${stage}`}]: ${message}`);
  return fail(code, message, stage);
}

/** The `invalid JSON:` preamble both seams answer with, byte for byte. */
export function jsonObject(body: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (error) {
    throw badRequest(`invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw badRequest("invalid JSON: expected a JSON object");
  }
  return parsed as Record<string, unknown>;
}
