import { Cause, Runtime } from "effect";

export type ErrorCode =
  | "bad_request"
  | "contract_mismatch"
  | "wallet_unsynced"
  | "wallet_busy"
  | "wallet_unfunded"
  | "proving_timeout"
  | "state_conflict"
  | "ambiguous_submit"
  | "internal";

export class PublisherError extends Error {
  /** The funding wallet's coins and sync progress when it failed, kept off `message`. */
  readonly walletState: string | undefined;

  constructor(
    readonly code: ErrorCode,
    message: string,
    options?: ErrorOptions & { readonly walletState?: string },
  ) {
    super(message, options);
    this.name = "PublisherError";
    this.walletState = options?.walletState;
  }
}

function describeOne(value: unknown): string {
  if (value instanceof Error) {
    return [value.name === "Error" ? "" : value.name, value.message].filter(Boolean).join(": ");
  }
  if (typeof value !== "object" || value === null) return String(value);
  const { _tag, message } = value as { _tag?: unknown; message?: unknown };
  const named = [_tag, message]
    .filter((part) => typeof part === "string" && part.length > 0)
    .join(": ");
  if (named.length > 0) return named;
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

// Effect's `FiberFailure` keeps its failure on a Symbol rather than in `cause`, and that
// failure carries the dependency's own reason (a node's RPC error, say) further down.
function causeOf(value: unknown): unknown {
  if (Runtime.isFiberFailure(value)) return Cause.squash(value[Runtime.FiberFailureCauseId]);
  return typeof value === "object" && value !== null
    ? (value as { cause?: unknown }).cause
    : undefined;
}

// `message` alone is not enough: Effect's `FiberFailure` keeps the failing class in `name`.
export function describeFailure(error: unknown): string {
  const parts: string[] = [];
  // Bounded, so a self-referential `cause` chain terminates rather than hangs.
  for (
    let current: unknown = error, depth = 0;
    current !== undefined && current !== null && depth < 8;
    depth += 1
  ) {
    const text = describeOne(current);
    if (text.length > 0 && !parts.some((part) => part.includes(text))) parts.push(text);
    current = causeOf(current);
  }
  return parts.join(": ") || String(error);
}

export function jsonObject(body: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (error) {
    throw new PublisherError(
      "bad_request",
      `invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new PublisherError("bad_request", "invalid JSON: expected a JSON object");
  }
  return parsed as Record<string, unknown>;
}
