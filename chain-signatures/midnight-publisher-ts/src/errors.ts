// Every rejected line is `{"code","message"}`. The code is the stable half a caller
// branches on; the message is evidence, reworded freely. A dependency's rendered
// cause chain goes to STDERR, never to stdout: stdout is the wire.

// Split by whose fault it is, which is the only thing the caller can act on: fix
// the request, fix the deployment, wait, or read the log.
export type ErrorCode =
  | "bad_request"
  // The deployed contract exposes no operation by the requested name, so the managed
  // dir was built for a different contract. Redeploy or repoint `MIDNIGHT_PUB_MANAGED_DIR`.
  // A NAME check, not a key check: a managed dir whose circuit names still match but
  // whose verifier keys have moved on passes it, and the caller pays to prove an Intent
  // the chain will then reject. Comparing keys needs the deployed ones, which only the
  // caller has.
  | "contract_mismatch"
  // Bytes on the wire carry a ledger tag this build does not speak, so the two halves
  // of the seam were compiled against different ledger crates. Nothing retries past this.
  | "ledger_mismatch"
  // No funding wallet: this deployment configured none, or the facade never synced one.
  | "wallet_unsynced"
  // Another submit holds the one dust UTXO. Retry when it answers, ~35s.
  | "wallet_busy"
  // No spendable dust right now: one wallet sustains roughly one submit per 35 seconds.
  | "wallet_unfunded"
  | "balance_failed"
  | "prove_failed"
  | "submit_rejected"
  // Someone wrote the contract state between the read the intent was built against and
  // the submit, so the transcript no longer replays. Read again and rebuild.
  | "state_conflict"
  | "internal";

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
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

// `message` alone is not enough: Effect's `FiberFailure` keeps the failing class in `name`.
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
