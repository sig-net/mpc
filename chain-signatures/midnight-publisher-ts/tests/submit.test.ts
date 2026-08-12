// The submit path against stubbed paid edges: the intent, the transaction it becomes
// and `Transaction.fromParts` are real; only the proof server and the funding wallet
// are stood in for. Real proving, balancing and submission are live-stack territory.

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { Transaction } from "@midnightntwrk/ledger-v9";
import { Data, Effect } from "effect";

import { PublisherError } from "../src/errors.js";
import { buildIntent } from "../src/intent.js";
import type { UnboundTransaction } from "../src/prover.js";
import {
  closePublisher,
  decodeIntent,
  handleSubmit,
  SUBMIT_TIMEOUT_MS,
  withDeadline,
} from "../src/submit.js";
import type { Landed } from "../src/wallet.js";
import {
  primeStub,
  respondInput,
  SINGLETON,
  STUB_TX_ID,
  testConfig,
  type StubEdges,
} from "./support.js";

const CONFIG = testConfig();

let intent: Uint8Array;

beforeAll(async () => {
  intent = await buildIntent(await respondInput());
}, 120_000);

afterEach(async () => {
  await closePublisher();
  vi.useRealTimers();
});

const failing = (message: string) => async (): Promise<never> => {
  throw new Error(message);
};

const refused = async (id: number): Promise<PublisherError> => {
  try {
    await handleSubmit(CONFIG, id, intent);
  } catch (error) {
    if (error instanceof PublisherError) return error;
    throw error;
  }
  throw new Error("expected the submit to be refused");
};

describe("decodeIntent", () => {
  it("classifies invalid intent bytes as bad requests", () => {
    for (const invalid of [Uint8Array.of(1, 2, 3), intent.subarray(0, 40)]) {
      expect(() => decodeIntent(invalid)).toThrowError(expect.objectContaining({ code: "bad_request" }) as Error);
    }
  });
});

describe("withDeadline", () => {
  it("rejects with the factory's error once the deadline passes", async () => {
    vi.useFakeTimers();
    const hang = new Promise<never>(() => undefined);
    const deadline = withDeadline(hang, 20, () => new PublisherError("internal", "took too long"));
    const rejected = expect(deadline).rejects.toMatchObject({ code: "internal" });

    await vi.advanceTimersByTimeAsync(20);
    await rejected;
  });

});

describe("handleSubmit: the flow", () => {
  it("carries the intent through prove, balance, finalize, and submit", async () => {
    const proven = { proven: true } as unknown as UnboundTransaction;
    let unproven: unknown;
    let balanced: unknown;
    let finalized: unknown;
    let submitted: unknown;
    primeStub({
      proveTx: async (tx) => {
        unproven = tx;
        return proven;
      },
      balanceTx: async (tx) => {
        balanced = tx;
        return tx;
      },
      finalizeTx: async (recipe) => {
        finalized = recipe;
        return recipe;
      },
      submitTx: async (tx) => {
        submitted = tx;
        return { txId: STUB_TX_ID };
      },
    });

    await expect(handleSubmit(CONFIG, 1, intent)).resolves.toEqual({ txId: STUB_TX_ID });

    expect(unproven).toBeInstanceOf(Transaction);
    expect(String(unproven)).toContain(SINGLETON);
    expect(balanced).toBe(proven);
    expect(finalized).toBe(proven);
    expect(submitted).toBe(proven);
  });

  it("classifies wallet failures for retry policy", async () => {
    for (const [message, code] of [
      ["Wallet.InsufficientFunds", "wallet_unfunded"],
      ["could not balance dust", "wallet_unfunded"],
      ["Transcript(Execution(ReadMismatch { expected: 06 }))", "state_conflict"],
    ] as const) {
      await closePublisher();
      primeStub({ balanceTx: failing(message) });

      expect((await refused(6)).code, message).toBe(code);
    }
  });

  it("finds the cause Effect hides on a Symbol, which is where the classification lives", async () => {
    // Every node error is wrapped in a constant-message SubmissionError; matching only
    // the rendered message would classify every rejection as a plain `internal`.
    class SubmissionError extends Data.TaggedError("SubmissionError")<{ message: string; cause?: unknown }> {}
    class TransactionInvalidError extends Data.TaggedError("TransactionInvalidError")<{ message: string }> {}
    primeStub({
      submitTx: () =>
        Effect.runPromise(
          Effect.fail(
            new SubmissionError({
              message: "Transaction submission error",
              cause: new TransactionInvalidError({
                message: "rejected by the node: Transcript(Execution(ReadMismatch))",
              }),
            }),
          ),
        ) as Promise<Landed>,
    });

    const refusal = await refused(8);

    expect(refusal.code).toBe("state_conflict");
    expect(refusal.message).toContain("Transaction submission error");
  });

});

describe("handleSubmit: the busy gate", () => {
  it("refuses a second submit while the first still holds the wallet", async () => {
    let release!: () => void;
    let entered!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const balancing = new Promise<void>((resolve) => {
      entered = resolve;
    });
    primeStub({
      balanceTx: async (tx) => {
        entered();
        await held;
        return tx;
      },
    });

    const first = handleSubmit(CONFIG, 1, intent);
    await balancing;

    const refusal = await refused(2);
    expect(refusal.code).toBe("wallet_busy");
    expect(refusal.message).toContain("request 1");

    release();
    await expect(first).resolves.toMatchObject({ txId: STUB_TX_ID });

    await expect(handleSubmit(CONFIG, 3, intent)).resolves.toMatchObject({ txId: STUB_TX_ID });
  });

  it("never claims the gate for a request that fails validation", async () => {
    primeStub();

    await expect(handleSubmit(CONFIG, 1, Uint8Array.of(1, 2, 3))).rejects.toMatchObject({ code: "bad_request" });
    await expect(handleSubmit(CONFIG, 2, intent)).resolves.toMatchObject({ txId: STUB_TX_ID });
  });

  it("does not let a refused submit leave the gate claimed", async () => {
    primeStub({ submitTx: failing("transaction rejected") as StubEdges["submitTx"] });
    expect((await refused(1)).code).toBe("internal");

    primeStub();
    await expect(handleSubmit(CONFIG, 2, intent)).resolves.toMatchObject({ txId: STUB_TX_ID });
  });

  it("keeps the gate claimed while an abandoned submit is still spending", async () => {
    vi.useFakeTimers();
    primeStub({ balanceTx: () => new Promise(() => undefined) });
    const pending = refused(1);
    await vi.advanceTimersByTimeAsync(SUBMIT_TIMEOUT_MS);
    const timedOut = await pending;
    expect(timedOut.code).toBe("ambiguous_submit");
    expect(timedOut.message).toMatch(/deadline/);
    expect(timedOut.message).toMatch(/may still land/);
    expect(timedOut.message).toContain("request 1");

    const refusal = await refused(2);
    expect(refusal.code).toBe("wallet_busy");
    expect(refusal.message).toContain("request 1");
  });

});
