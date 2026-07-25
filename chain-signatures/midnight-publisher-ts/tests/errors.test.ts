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
import { describe, expect, it } from "vitest";

import { classify, fail, RESPOND_STAGES, statusFor, type ErrorCode } from "../src/errors.js";
import { describeFailure } from "../src/respond.js";

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

/** What `inStage` classifies against: the message plus Effect's rendered cause chain. */
function haystack(error: unknown): string {
  return `${describeFailure(error)}\n${String(error)}`;
}

describe("the wallet's dust shortfall", () => {
  it("survives into describeFailure and reaches wallet_unfunded", async () => {
    // `DustWallet` runs its Effect with no outer wrapper, so `Data.TaggedError`'s
    // tag lands in `name` and the message is the balancer's own template.
    const error = await fiberFailure(
      new InsufficientFundsError({ message: "Insufficient Funds: could not balance dust" }),
    );
    expect(describeFailure(error)).toBe(
      "(FiberFailure) Wallet.InsufficientFunds: Insufficient Funds: could not balance dust",
    );
    expect(classify(RESPOND_STAGES.balance, haystack(error))).toBe("wallet_unfunded");
  });
});

describe("the submission wrapper", () => {
  it("flattens the message, so the message alone cannot classify", async () => {
    // The defect this file exists to catch: every submit failure renders
    // identically, whatever went wrong underneath.
    const error = await fiberFailure(
      new SubmissionError({
        message: "Transaction submission error",
        cause: new TransactionInvalidError({
          message: "Transaction is invalid and was rejected by the node: Transcript(Execution(ReadMismatch))",
        }),
      }),
    );
    expect(describeFailure(error)).toBe("(FiberFailure) SubmissionError: Transaction submission error");
    expect(classify(RESPOND_STAGES.submit, describeFailure(error))).toBe("submit_rejected");
  });

  it("still reaches state_conflict once the rendered cause chain is included", async () => {
    const error = await fiberFailure(
      new SubmissionError({
        message: "Transaction submission error",
        cause: new TransactionInvalidError({
          message: "Transaction is invalid and was rejected by the node: Transcript(Execution(ReadMismatch))",
        }),
      }),
    );
    expect(classify(RESPOND_STAGES.submit, haystack(error))).toBe("state_conflict");
  });
});

describe("the fallbacks", () => {
  it("name the stage when nothing matches", async () => {
    const error = await fiberFailure(new SubmissionError({ message: "Transaction submission error" }));
    expect(classify(RESPOND_STAGES.submit, haystack(error))).toBe("submit_rejected");
    expect(classify(RESPOND_STAGES.balance, haystack(error))).toBe("balance_failed");
    expect(classify(RESPOND_STAGES.read, haystack(error))).toBe("node_unavailable");
    expect(classify(RESPOND_STAGES.prove, haystack(error))).toBe("prove_failed");
  });
});

describe("the status map", () => {
  it("separates retry-as-is from never-retry inside one status", () => {
    expect(statusFor("state_conflict")).toBe(409);
    expect(statusFor("contract_mismatch")).toBe(409);
  });

  it("gives every code a non-2xx status", () => {
    const codes: readonly ErrorCode[] = [
      "bad_request", "not_found", "decode_failed", "ledger_mismatch",
      "contract_absent", "contract_mismatch", "state_conflict", "node_unavailable",
      "prove_failed", "wallet_unfunded", "wallet_unsynced", "wallet_busy",
      "balance_failed", "submit_rejected", "internal",
    ];
    for (const code of codes) expect(statusFor(code)).toBeGreaterThanOrEqual(400);
  });

  it("marks every wallet condition 503: back off and retry, the request itself is fine", () => {
    expect(statusFor("wallet_unfunded")).toBe(503);
    expect(statusFor("wallet_unsynced")).toBe(503);
    expect(statusFor("wallet_busy")).toBe(503);
  });
});

/** Scrubs nothing, deliberately: secrecy is held upstream in `wallet.ts`. These pin the reply shape. */
describe("the reply funnel", () => {
  it("carries the message through verbatim, status from the code", () => {
    const reply = fail("contract_absent", "no contract at that address");
    expect(reply.status).toBe(409);
    expect(JSON.parse(reply.body)).toEqual({ code: "contract_absent", message: "no contract at that address" });
  });

  it("carries detail when given, and omits the key when not", () => {
    const withDetail = fail("submit_rejected", "flat message", undefined, "submit", "the node's rendered cause chain");
    expect(JSON.parse(withDetail.body)).toMatchObject({ detail: "the node's rendered cause chain" });
    expect(JSON.parse(fail("submit_rejected", "flat message").body)).toEqual({
      code: "submit_rejected",
      message: "flat message",
    });
  });

  it("carries the stage when one is given, and omits the key when not", () => {
    // The stage is the machine-readable half the caller's alerting branches on;
    // an absent stage must be an absent key, not a null, so the caller's strict
    // parser can make the field optional.
    const staged = fail("submit_rejected", "the chain refused it", undefined, "submit");
    expect(JSON.parse(staged.body)).toEqual({ code: "submit_rejected", message: "the chain refused it", stage: "submit" });
    const unstaged = fail("submit_rejected", "the chain refused it");
    expect(JSON.parse(unstaged.body)).toEqual({ code: "submit_rejected", message: "the chain refused it" });
  });
});
