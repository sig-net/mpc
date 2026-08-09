// The submit path against stubbed paid edges: the intent, the transaction it becomes
// and `Transaction.fromParts` are real; only the proof server and the funding wallet
// are stood in for. Real proving, balancing and submission are live-stack territory.

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { LedgerParameters, Transaction } from "@midnightntwrk/ledger-v9";
import { Data, Effect } from "effect";

import { PublisherError } from "../src/errors.js";
import { buildIntent } from "../src/intent.js";
import type { UnboundTransaction } from "../src/prover.js";
import {
  closePublisher,
  decodeIntent,
  handleSubmit,
  primePublisher,
  SUBMIT_TIMEOUT,
  withDeadline,
  type Publisher,
} from "../src/submit.js";
import type { FundingWallet, Landed } from "../src/wallet.js";
import { initialSingletonStateHex, managedDir, testConfig, toHex } from "./support.js";

const SINGLETON = "d7b3c45da613be25050bbdf3fde4cef8f66154d3a52ca8c1edd878bd6391f169";
const REQUEST_ID = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";

const CONFIG = testConfig();

const TX_ID = "ab".repeat(32);
const BLOCK_HASH = "cd".repeat(32);

let intent: Uint8Array;

beforeAll(async () => {
  intent = await buildIntent(managedDir(), {
    circuit: "respond",
    contractAddress: SINGLETON,
    requestId: REQUEST_ID,
    signature: { bigR: { x: "11".repeat(32), y: "22".repeat(32) }, s: "33".repeat(32), recoveryId: 0 },
    contractState: await initialSingletonStateHex(),
    ledgerParameters: toHex(LedgerParameters.initialParameters().serialize()),
    coinPublicKey: "44".repeat(32),
    ttlSeconds: 1_800_000_000,
  });
}, 120_000);

interface Edges {
  readonly proveTx?: (tx: unknown) => Promise<unknown>;
  readonly balanceTx?: (tx: unknown) => Promise<unknown>;
  readonly finalizeTx?: (recipe: unknown) => Promise<unknown>;
  readonly submitTx?: (tx: unknown) => Promise<Landed>;
}

// Identity by default, so a sentinel passed in at one edge is observable at the next.
function primeStub(edges: Edges = {}): void {
  const wallet = {
    balanceTx: edges.balanceTx ?? (async (tx: unknown) => tx),
    finalizeTx: edges.finalizeTx ?? (async (recipe: unknown) => recipe),
    submitTx: edges.submitTx ?? (async () => ({ txId: TX_ID, blockHash: BLOCK_HASH })),
    close: async () => undefined,
  } as unknown as FundingWallet;

  primePublisher(
    Promise.resolve({
      proveTx: edges.proveTx ?? (async (tx: unknown) => tx),
      wallet,
    } as unknown as Publisher),
  );
}

const PRODUCTION_TIMEOUT = SUBMIT_TIMEOUT.ms;

afterEach(async () => {
  await closePublisher();
  SUBMIT_TIMEOUT.ms = PRODUCTION_TIMEOUT;
});

const failing = (code: string, message: string) => async (): Promise<never> => {
  void code;
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
  it("reads back what the builder wrote, with its one call intact", () => {
    expect(decodeIntent(intent).actions).toHaveLength(1);
  });

  it("names the field when the bytes are not a tagged intent at all", () => {
    expect(() => decodeIntent(Uint8Array.of(1, 2, 3))).toThrowError(/`intent` is not a midnight:intent\[v9\] blob/);
    expect(() => decodeIntent(Uint8Array.of(1, 2, 3))).toThrowError(
      expect.objectContaining({ code: "bad_request" }) as Error,
    );
  });

  it("calls a different version of the same tag a ledger mismatch, not a bad request", () => {
    // Nothing the caller sends can fix a seam built against two different ledger crates.
    const skewed = Uint8Array.from(intent);
    skewed[Buffer.from(skewed).indexOf("midnight:intent[v") + "midnight:intent[v".length] = "8".charCodeAt(0);

    expect(() => decodeIntent(skewed)).toThrowError(expect.objectContaining({ code: "ledger_mismatch" }) as Error);
  });

  it("answers bad_request when the tag is right and the body is not", () => {
    const truncated = intent.subarray(0, 40);

    expect(() => decodeIntent(truncated)).toThrowError(/`intent` did not deserialize/);
  });
});

describe("withDeadline", () => {
  it("passes a timely result through", async () => {
    await expect(withDeadline(Promise.resolve(7), 1_000, () => new Error("never"))).resolves.toBe(7);
  });

  it("rejects with the factory's error once the deadline passes", async () => {
    const hang = new Promise<never>(() => undefined);

    await expect(withDeadline(hang, 20, () => new PublisherError("internal", "took too long"))).rejects.toMatchObject({
      code: "internal",
    });
  });

  it("leaves the abandoned attempt's late failure handled", async () => {
    // An unhandled rejection from the losing side would kill a process holding a hot wallet.
    const unhandled: unknown[] = [];
    const record = (reason: unknown): void => void unhandled.push(reason);
    process.on("unhandledRejection", record);
    try {
      const late = new Promise<never>((_, reject) => setTimeout(() => reject(new Error("late")), 20));
      await expect(withDeadline(late, 5, () => new Error("deadline"))).rejects.toThrow("deadline");
      await new Promise((resolve) => setTimeout(resolve, 40));
      expect(unhandled).toEqual([]);
    } finally {
      process.off("unhandledRejection", record);
    }
  });
});

describe("handleSubmit: the flow", () => {
  it("answers the transaction id and the block it landed in", async () => {
    primeStub();

    await expect(handleSubmit(CONFIG, 1, intent)).resolves.toEqual({ txId: TX_ID, blockHash: BLOCK_HASH });
  });

  it("wraps the intent into a transaction that carries it, and proves that one", async () => {
    let proved: unknown;
    primeStub({
      proveTx: async (tx) => {
        proved = tx;
        return tx;
      },
    });

    await handleSubmit(CONFIG, 1, intent);

    expect(proved).toBeInstanceOf(Transaction);
    expect(String(proved)).toContain(SINGLETON);
  });

  it("carries the proven transaction through balance and finalize into submit", async () => {
    const proven = { proven: true } as unknown as UnboundTransaction;
    let balanced: unknown;
    let finalized: unknown;
    let submitted: unknown;
    primeStub({
      proveTx: async () => proven,
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
        return { txId: TX_ID, blockHash: BLOCK_HASH };
      },
    });

    await handleSubmit(CONFIG, 1, intent);

    expect(balanced).toBe(proven);
    expect(finalized).toBe(proven);
    expect(submitted).toBe(proven);
  });

  it("refuses a submit on a deployment that configured no wallet", async () => {
    await closePublisher();
    const refusal = await refused(4);

    expect(refusal.code).toBe("wallet_unsynced");
    expect(refusal.message).toContain("MIDNIGHT_PUB_FUNDING_SEED");
    expect(refusal.message).toContain("MIDNIGHT_PUB_NODE_URL");
  });

  it("refines a dust shortfall into wallet_unfunded, which means back off rather than retry", async () => {
    // The wallet SDK raises the tagged error and the balancer raises the sentence.
    for (const spelling of ["Wallet.InsufficientFunds", "could not balance dust"]) {
      await closePublisher();
      primeStub({ balanceTx: failing("balance", spelling) });

      expect((await refused(6)).code, spelling).toBe("wallet_unfunded");
    }
  });

  it("refines an optimistic-concurrency loss into state_conflict", async () => {
    primeStub({
      submitTx: failing("submit", "Transcript(Execution(ReadMismatch { expected: 06 }))") as Edges["submitTx"],
    });

    expect((await refused(7)).code).toBe("state_conflict");
  });

  it("finds the cause Effect hides on a Symbol, which is where the classification lives", async () => {
    // Every node error is wrapped in a constant-message SubmissionError; matching only
    // the rendered message would classify every rejection as a plain `submit_rejected`.
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

  it("plumbs a wallet that never opened out to the caller as its own code", async () => {
    primePublisher(Promise.reject(new PublisherError("wallet_unsynced", "the funding wallet could not sync")));

    expect((await refused(9)).code).toBe("wallet_unsynced");
  });
});

describe("handleSubmit: the busy gate", () => {
  it("refuses a second submit while the first still holds the wallet", async () => {
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    primeStub({
      balanceTx: async (tx) => {
        await held;
        return tx;
      },
    });

    const first = handleSubmit(CONFIG, 1, intent);
    await new Promise((resolve) => setTimeout(resolve, 10));

    const refusal = await refused(2);
    expect(refusal.code).toBe("wallet_busy");
    expect(refusal.message).toContain("request 1");

    release();
    await expect(first).resolves.toMatchObject({ txId: TX_ID });

    await expect(handleSubmit(CONFIG, 3, intent)).resolves.toMatchObject({ txId: TX_ID });
  });

  it("never claims the gate for a request that fails validation", async () => {
    primeStub();

    await expect(handleSubmit(CONFIG, 1, Uint8Array.of(1, 2, 3))).rejects.toMatchObject({ code: "bad_request" });
    await expect(handleSubmit(CONFIG, 2, intent)).resolves.toMatchObject({ txId: TX_ID });
  });

  it("does not let a refused submit leave the gate claimed", async () => {
    primeStub({ submitTx: failing("submit", "transaction rejected") as Edges["submitTx"] });
    expect((await refused(1)).code).toBe("internal");

    await closePublisher();
    primeStub();
    await expect(handleSubmit(CONFIG, 2, intent)).resolves.toMatchObject({ txId: TX_ID });
  });

  it("keeps the gate claimed while an abandoned submit is still spending", async () => {
    SUBMIT_TIMEOUT.ms = 50;
    primeStub({ balanceTx: () => new Promise(() => undefined) });
    expect((await refused(1)).code).toBe("internal");

    SUBMIT_TIMEOUT.ms = PRODUCTION_TIMEOUT;
    const refusal = await refused(2);
    expect(refusal.code).toBe("wallet_busy");
    expect(refusal.message).toContain("request 1");
  });

  it("never lets two submits balance at once, even across a blown deadline", async () => {
    let live = 0;
    let peak = 0;
    primeStub({
      balanceTx: async (tx) => {
        live += 1;
        peak = Math.max(peak, live);
        await new Promise((resolve) => setTimeout(resolve, 300));
        live -= 1;
        return tx;
      },
    });

    SUBMIT_TIMEOUT.ms = 100;
    expect((await refused(1)).code).toBe("internal");

    SUBMIT_TIMEOUT.ms = PRODUCTION_TIMEOUT;
    await handleSubmit(CONFIG, 2, intent).catch(() => undefined);
    expect(peak).toBe(1);
    await new Promise((resolve) => setTimeout(resolve, 400));
  });

  it("tells the caller its abandoned submit may still land, rather than that it failed", async () => {
    // A caller that reads this as "did not land" and retries posts the same signature twice.
    SUBMIT_TIMEOUT.ms = 30;
    primeStub({ balanceTx: () => new Promise(() => undefined) });

    const refusal = await refused(11);

    expect(refusal.message).toMatch(/deadline/);
    expect(refusal.message).toMatch(/may still land/);
    expect(refusal.message).toContain("request 11");
  });
});
