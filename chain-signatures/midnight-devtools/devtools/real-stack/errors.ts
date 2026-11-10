import { Cause, Runtime } from "effect";

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
