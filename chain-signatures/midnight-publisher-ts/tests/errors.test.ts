/**
 * The two failures worth acting on differently are identified by matching a
 * substring of a dependency's error text, which is the most fragile thing here.
 *
 * These build the failures through a REAL `Effect.runPromise` rejection, not a
 * hand-set `.name`. The first version of this file fabricated them with
 * `new Error()` plus a `.name`, passed, and proved nothing: it missed that
 * `submissionService` flattens every node error into a constant-message
 * `SubmissionError` whose cause Effect stores on a Symbol rather than `.cause`.
 * That is the same self-consistent-test trap `block.ts` warns about for the `Fr`
 * tag byte, and it hid an unreachable error code.
 *
 * Still NOT proven here: that the node client surfaces the ledger's own
 * `ReadMismatch` text at all. That needs a live same-id race.
 */

import { Data, Effect } from "effect";
import { describe, expect, it, vi } from "vitest";

import { describeFailure, fail, STATUS, type ErrorCode } from "../src/errors.js";


class InsufficientFundsError extends Data.TaggedError("Wallet.InsufficientFunds")<{
  readonly message: string;
}> {}
class SubmissionError extends Data.TaggedError("SubmissionError")<{
  readonly message: string;
  readonly cause?: unknown;
}> {}
class TransactionInvalidError extends Data.TaggedError("TransactionInvalidError")<{
  readonly message: string;
}> {}

/** Reject through Effect so the value is a genuine `FiberFailure`. */
async function fiberFailure(error: unknown): Promise<unknown> {
  try {
    await Effect.runPromise(Effect.fail(error));
    throw new Error("expected the effect to fail");
  } catch (caught) {
    return caught;
  }
}

/**
 * What `step` matches against: the message ALONE is not enough, which is why it
 * searches the rendered cause chain too. The code each text maps to is pinned
 * end to end in `respond-path.test.ts`, through the real handler.
 */
describe("what the wallet and the submission wrapper actually render", () => {
  it("keeps the dust shortfall's tag and message intact", async () => {
    // `DustWallet` runs its Effect with no outer wrapper, so `Data.TaggedError`'s
    // tag lands in `name` and the message is the balancer's own template.
    const error = await fiberFailure(
      new InsufficientFundsError({ message: "Insufficient Funds: could not balance dust" }),
    );
    expect(describeFailure(error)).toBe(
      "(FiberFailure) Wallet.InsufficientFunds: Insufficient Funds: could not balance dust",
    );
  });

  it("flattens every submit failure to one constant message", async () => {
    // The defect this file exists to catch: every submit failure renders
    // identically, whatever went wrong underneath, so `ReadMismatch` survives
    // only in `String(error)` and never in the message.
    const error = await fiberFailure(
      new SubmissionError({
        message: "Transaction submission error",
        cause: new TransactionInvalidError({
          message: "Transaction is invalid and was rejected by the node: Transcript(Execution(ReadMismatch))",
        }),
      }),
    );
    expect(describeFailure(error)).toBe("(FiberFailure) SubmissionError: Transaction submission error");
    expect(describeFailure(error)).not.toContain("ReadMismatch");
    expect(`${describeFailure(error)}\n${String(error)}`).toContain("ReadMismatch");
  });
});

describe("the status map", () => {
  it("gives every code a non-2xx status", () => {
    const codes: readonly ErrorCode[] = [
      "bad_request", "not_found", "decode_failed", "ledger_mismatch",
      "contract_absent", "contract_mismatch", "state_conflict", "node_unavailable",
      "prove_failed", "wallet_unfunded", "wallet_unsynced", "wallet_busy",
      "balance_failed", "submit_rejected", "internal",
    ];
    for (const code of codes) expect(STATUS[code]).toBeGreaterThanOrEqual(400);
  });

});

/** Scrubs nothing, deliberately: secrecy is held upstream in `wallet.ts`. These pin the reply shape. */
describe("the reply funnel", () => {
  it("keeps the evidence in the log and out of the body", () => {
    // The split that lets the wire stay `{code, message}`: an operator gets the
    // whole rendered chain, a caller that branches on `code` gets none of it.
    const logged: unknown[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((line: unknown) => void logged.push(line));
    try {
      const reply = fail("submit_rejected", "flat message", "submit failed", new Error("Transcript(ReadMismatch)"));
      expect(JSON.parse(reply.body)).toEqual({ code: "submit_rejected", message: "flat message" });
      expect(logged.join("\n")).toContain("Transcript(ReadMismatch)");
    } finally {
      spy.mockRestore();
    }
  });
});
