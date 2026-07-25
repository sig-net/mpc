/**
 * Every non-200 is `{"code","message"}` plus, on the respond path, the `stage`
 * that failed (`boot|read|prove|balance|submit`) and, when a dependency's
 * rendered cause chain says more than its one-line message, a `detail`
 * carrying that chain. The code and stage are the stable halves a caller
 * branches on; message and detail are evidence, reworded freely.
 */

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
  constructor(readonly code: ErrorCode, message: string, readonly stage?: string, readonly detail?: string) {
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
 * The only place this service matches on dependency error TEXT, pinned by
 * `tests/errors.test.ts`; a pattern that stops matching degrades to the stage
 * fallback. `Wallet.InsufficientFunds` is confirmed reachable. `ReadMismatch`
 * is best-effort: `submissionService` flattens node errors to a constant
 * message, so it can only surface in the rendered cause chain.
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
 * The single funnel, so status and body cannot disagree. `logLabel` omitted
 * means silent; a `bad_request` is the caller's own mistake.
 */
export function fail(code: ErrorCode, message: string, logLabel?: string, stage?: string, detail?: string): Reply {
  if (logLabel !== undefined && code !== "bad_request") {
    console.error(`${logLabel} [${code}${stage === undefined ? "" : ` @${stage}`}]: ${message}${detail === undefined ? "" : `\n${detail}`}`);
  }
  const body = { code, message, ...(stage === undefined ? {} : { stage }), ...(detail === undefined ? {} : { detail }) };
  return { status: statusFor(code), body: JSON.stringify(body) };
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
