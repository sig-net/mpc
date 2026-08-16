// The submit path against stubbed paid edges: the intent, the transaction it becomes
// and `Transaction.fromParts` are real; only the proof server and the funding wallet
// are stood in for. Real proving, balancing and submission are live-stack territory.

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { Transaction } from "@midnightntwrk/ledger-v9";
import { Data, Effect } from "effect";

vi.mock("../src/wallet.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/wallet.js")>();
  return { ...original, openFundingWallet: vi.fn(original.openFundingWallet) };
});

import { PublisherError } from "../src/errors.js";
import { buildIntent } from "../src/intent.js";
import type { UnboundTransaction } from "../src/prover.js";
import {
  closePublisher,
  handleSubmit,
  primePublisher,
  shutdownPublisher,
  SUBMIT_TIMEOUT_MS,
  type Publisher,
  warmupPublisher,
} from "../src/submit.js";
import { openFundingWallet, type FundingWallet, type Landed } from "../src/wallet.js";
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

describe("publisher lifecycle", () => {
  it("bounds shutdown while the wallet close is pending", async () => {
    vi.useFakeTimers();
    let closeStarted = false;
    primePublisher(
      Promise.resolve({
        proveTx: async () => {
          throw new Error("not used");
        },
        wallet: {
          close: () => {
            closeStarted = true;
            return new Promise<void>(() => undefined);
          },
        },
      } as unknown as Publisher),
    );

    const closing = shutdownPublisher();
    await vi.runAllTimersAsync();

    expect(closeStarted).toBe(true);
    await expect(closing).resolves.toBeUndefined();
  });
});

describe("handleSubmit: the flow", () => {
  it("carries the intent through prove, balance, finalize, and submit", async () => {
    const proven = { proven: true } as unknown as UnboundTransaction;
    const order: string[] = [];
    let proofBudgetMs: number | undefined;
    let unproven: unknown;
    let balanced: unknown;
    let finalized: unknown;
    let submitted: unknown;
    primeStub({
      requireReady: async () => {
        order.push("ready");
      },
      proveTx: async (tx, budgetMs) => {
        order.push("prove");
        proofBudgetMs = budgetMs;
        unproven = tx;
        return proven;
      },
      balanceTx: async (tx) => {
        order.push("balance");
        balanced = tx;
        return tx;
      },
      finalizeTx: async (recipe) => {
        order.push("finalize");
        finalized = recipe;
        return recipe;
      },
      submitTx: async (tx) => {
        order.push("submit");
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
    expect(proofBudgetMs).toBeGreaterThan(0);
    expect(proofBudgetMs).toBeLessThanOrEqual(SUBMIT_TIMEOUT_MS);
    expect(order).toEqual(["ready", "prove", "balance", "finalize", "submit"]);
  });

  it("does not start wallet work when proving consumes the absolute deadline", async () => {
    let now = 0;
    const clock = vi.spyOn(performance, "now").mockImplementation(() => now);
    const proveTx = vi.fn(async (tx: unknown) => {
      now = SUBMIT_TIMEOUT_MS;
      return tx;
    });
    const balanceTx = vi.fn(async (tx: unknown) => tx);
    primeStub({
      proveTx,
      balanceTx,
    });

    try {
      const refusal = await refused(3);
      expect(refusal).toMatchObject({
        code: "proving_timeout",
        message: expect.stringMatching(/no wallet operation started.*retry is safe/i),
      });
      expect(proveTx).toHaveBeenCalledOnce();
      expect(balanceTx).not.toHaveBeenCalled();
    } finally {
      clock.mockRestore();
    }

    primeStub();
    await expect(handleSubmit(CONFIG, 4, intent)).resolves.toMatchObject({ txId: STUB_TX_ID });
  });

  it("classifies wallet failures for retry policy", async () => {
    for (const [message, code] of [
      ["Wallet.InsufficientFunds", "wallet_unfunded"],
      ["Insufficient Funds: could not balance dust", "wallet_unfunded"],
      // The SDK's texts for a node refusal, neither of which carries the ledger's reason.
      [
        "TransactionInvalidError: Transaction is invalid and was rejected by the node",
        "state_conflict",
      ],
      ["1010: Invalid Transaction: Custom error: 170", "state_conflict"],
      [
        "TransactionDroppedError: Transaction got dropped, the mempool likely is full and network congested",
        "internal",
      ],
    ] as const) {
      await closePublisher();
      primeStub({ balanceTx: failing(message) });

      expect((await refused(6)).code, message).toBe(code);
    }
  });

  it("finds the cause Effect hides on a Symbol, which is where the classification lives", async () => {
    // Every node error is wrapped in a constant-message SubmissionError; matching only
    // the rendered message would classify every rejection as a plain `internal`.
    class SubmissionError extends Data.TaggedError("SubmissionError")<{
      message: string;
      cause?: unknown;
    }> {}
    class TransactionInvalidError extends Data.TaggedError("TransactionInvalidError")<{
      message: string;
    }> {}
    primeStub({
      submitTx: () =>
        Effect.runPromise(
          Effect.fail(
            new SubmissionError({
              message: "Transaction submission error",
              cause: new TransactionInvalidError({
                message: "Transaction is invalid and was rejected by the node",
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

describe("handleSubmit: publisher preflight", () => {
  it("times out pending startup as wallet_unsynced, leaves the gate free, and reuses the memoized build", async () => {
    vi.useFakeTimers();
    await closePublisher();
    vi.mocked(openFundingWallet).mockClear();
    const wallet = {
      requireReady: vi.fn(async () => undefined),
      close: vi.fn(async () => undefined),
    } as unknown as FundingWallet;
    let release!: (ready: FundingWallet) => void;
    const opening = new Promise<FundingWallet>((resolve) => {
      release = resolve;
    });
    vi.mocked(openFundingWallet).mockReturnValue(opening);
    let observed: unknown;
    const first = handleSubmit(CONFIG, 10, intent).then(
      (landed) => {
        observed = landed;
        return landed;
      },
      (error: unknown) => {
        observed = error;
        return error;
      },
    );

    try {
      await vi.advanceTimersByTimeAsync(60_000);
      expect(observed).toBeUndefined();
      await vi.advanceTimersByTimeAsync(SUBMIT_TIMEOUT_MS - 60_000);
      expect(observed).toMatchObject({ code: "wallet_unsynced" });

      release(wallet);
      await opening;
      warmupPublisher(CONFIG);
      await Promise.resolve();
      expect(openFundingWallet).toHaveBeenCalledOnce();
      await closePublisher();

      primeStub();
      await expect(handleSubmit(CONFIG, 11, intent)).resolves.toMatchObject({ txId: STUB_TX_ID });
    } finally {
      release(wallet);
      await first.catch(() => undefined);
    }
  });

  it("counts initial indexing time against the same absolute submit deadline", async () => {
    vi.useFakeTimers();
    let releaseBalance!: () => void;
    const heldBalance = new Promise<void>((resolve) => {
      releaseBalance = resolve;
    });
    let proofBudgetMs: number | undefined;
    const proveTx = vi.fn(async (tx: unknown, budgetMs: number) => {
      proofBudgetMs = budgetMs;
      return tx;
    });
    primeStub({
      requireReady: () => new Promise<void>((resolve) => setTimeout(resolve, 30_000)),
      proveTx,
      balanceTx: async (tx) => {
        await heldBalance;
        return tx;
      },
    });
    let observed: unknown;
    const submission = handleSubmit(CONFIG, 14, intent).then(
      (landed) => {
        observed = landed;
        return landed;
      },
      (error: unknown) => {
        observed = error;
        return error;
      },
    );

    await vi.advanceTimersByTimeAsync(29_999);
    const provedBeforeIndexing = proveTx.mock.calls.length;
    await vi.advanceTimersByTimeAsync(1);
    expect(proveTx).toHaveBeenCalledOnce();
    expect(proofBudgetMs).toBe(SUBMIT_TIMEOUT_MS - 30_000);
    await vi.advanceTimersByTimeAsync(SUBMIT_TIMEOUT_MS - 30_001);
    expect(observed).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    const outcomeAtAbsoluteDeadline = observed;

    releaseBalance();
    await submission;
    expect(provedBeforeIndexing).toBe(0);
    expect(outcomeAtAbsoluteDeadline).toMatchObject({ code: "ambiguous_submit" });
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

    for (const invalid of [Uint8Array.of(1, 2, 3), intent.subarray(0, 40)]) {
      await expect(handleSubmit(CONFIG, 1, invalid)).rejects.toMatchObject({
        code: "bad_request",
      });
    }
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
    expect(timedOut.message).toMatch(/may still land/);
    expect(timedOut.message).toContain("request 1");

    const refusal = await refused(2);
    expect(refusal.code).toBe("wallet_busy");
    expect(refusal.message).toContain("request 1");
  });
});
