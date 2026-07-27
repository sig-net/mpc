// `POST /respond` orchestration tests, offline: a stub node client serving
// captured fixture blobs and a publisher primed through the test seam from the
// real contract assets and real derived keys. The circuit itself really runs, so
// what these prove is the flow: deadline, busy gate, classification, wire shape.
//
// NOT covered here, and covered by `tests/respond-live.ts` instead: the real
// wallet facade, real proving, and real submission.

import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";

import { LedgerParameters, ZswapChainState } from "@midnightntwrk/ledger-v9";
import { ContractExecutable } from "@midnight-ntwrk/midnight-js-protocol/compact-js";
import { deserializeCompactContractState } from "@midnight-ntwrk/midnight-js-utils";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import { setNetworkId } from "@midnight-ntwrk/midnight-js/network-id";
import {
  Contract as SignetContract,
  type SignetContractCircuitId,
  type SignetContractPrivateState,
} from "@sig-net/midnight-contract";
import { GENESIS_MINT_WALLET_SEED, makeVacantCompiledContract } from "@sig-net/midnight-contract-deploy";
import { Data, Effect } from "effect";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import type { Config } from "../src/config.js";
import { PublisherError, type Reply } from "../src/errors.js";
import type { NodeClient } from "../src/node.js";
import {
  closePublisher,
  handleRespond,
  primePublisher,
  RESPOND_TIMEOUT,
  withDeadline,
  type Publisher,
} from "../src/respond.js";
import { deriveFundingKeys, type FundingWallet } from "../src/wallet.js";
import { FIXTURES, listening } from "./support.js";

const MANAGED = fileURLToPath(new URL("../node_modules/@sig-net/midnight-contract/dist/managed/", import.meta.url));

const SINGLETON = "d7b3c45da613be25050bbdf3fde4cef8f66154d3a52ca8c1edd878bd6391f169";

const HEAD_BARE = "ab".repeat(32);

const TEST_CONFIG: Config = {
  port: 0,
  bindHost: "127.0.0.1",
  nodeUrl: "ws://127.0.0.1:1",
  proofServerUrl: "http://127.0.0.1:1",
  indexerUrl: "http://127.0.0.1:1",
  indexerWsUrl: "ws://127.0.0.1:1",
  managedDir: MANAGED,
  networkId: "undeployed",
};

// The circuit is a blind append, so any 32-byte values do.
function respondBody(rid: string): string {
  return JSON.stringify({
    contract_address: SINGLETON,
    circuit: "respond",
    request_id: rid,
    signature: {
      big_r: { x: "11".repeat(32), y: "22".repeat(32) },
      s: "33".repeat(32),
      recovery_id: 0,
    },
  });
}

function parseBody(reply: Reply): Record<string, unknown> {
  return JSON.parse(reply.body) as Record<string, unknown>;
}

type RuntimeResult = { isOk: boolean; asOk: { toU8a: (bare?: boolean) => Uint8Array } };

const ok = (bytes: Uint8Array): RuntimeResult => ({ isOk: true, asOk: { toU8a: () => bytes } });
const runtimeError: RuntimeResult = { isOk: false, asOk: { toU8a: () => Uint8Array.of() } };

interface StubReads {
  readonly head?: () => Promise<{ toHex: () => string }>;
  readonly contract?: () => Promise<RuntimeResult>;
  readonly zswap?: () => Promise<RuntimeResult>;
  readonly params?: () => Promise<RuntimeResult>;
}

// Only the shape `readCallStates` touches; everything else is unreachable by construction.
function stubClient(overrides: StubReads = {}): NodeClient {
  const reads: Required<StubReads> = {
    head: async () => ({ toHex: () => `0x${HEAD_BARE}` }),
    contract: async () => ok(Uint8Array.from(readFileSync(`${FIXTURES}respond-singleton-state-37571.mn`))),
    zswap: async () => ok(new ZswapChainState().serialize()),
    params: async () => ok(LedgerParameters.initialParameters().serialize()),
    ...overrides,
  };
  return {
    rpc: { chain: { getFinalizedHead: reads.head } },
    at: async () => ({
      call: {
        midnightRuntimeApi: {
          getContractState: reads.contract,
          getZswapChainState: reads.zswap,
          getLedgerParameters: reads.params,
        },
      },
    }),
  } as unknown as NodeClient;
}

interface StubEdges {
  readonly proveTx?: (tx: unknown) => Promise<unknown>;
  readonly balanceTx?: (tx: unknown) => Promise<unknown>;
  readonly submitTx?: (tx: unknown) => Promise<string>;
  readonly verifierKeys?: Publisher["verifierKeys"];
}

let realVerifierKeys: Publisher["verifierKeys"];
let zkConfigProvider: NodeZkConfigProvider<SignetContractCircuitId>;
let compiledContract: ReturnType<
  typeof makeVacantCompiledContract<SignetContract<SignetContractPrivateState>, SignetContractPrivateState>
>;

beforeAll(async () => {
  // Baked into address encoding; `buildPublisher` normally does this and the seam bypasses it.
  setNetworkId(TEST_CONFIG.networkId);
  zkConfigProvider = new NodeZkConfigProvider<SignetContractCircuitId>(MANAGED);
  compiledContract = makeVacantCompiledContract<SignetContract<SignetContractPrivateState>, SignetContractPrivateState>(
    "signet-contract",
    SignetContract,
    MANAGED,
  );
  realVerifierKeys = await zkConfigProvider.getVerifierKeys(
    ContractExecutable.make(compiledContract).getProvableCircuitIds(),
  );
});

function primeStub(edges: StubEdges = {}): void {
  const keys = deriveFundingKeys(GENESIS_MINT_WALLET_SEED, TEST_CONFIG.networkId);
  const wallet = {
    getCoinPublicKey: () => keys.shieldedSecretKeys.coinPublicKey,
    getEncryptionPublicKey: () => keys.shieldedSecretKeys.encryptionPublicKey,
    balanceTx: edges.balanceTx ?? (async (tx: unknown) => tx),
    submitTx: edges.submitTx ?? (async () => "aa".repeat(32)),
    close: async () => undefined,
  } as unknown as FundingWallet;

  primePublisher(
    Promise.resolve({
      wallet,
      zkConfigProvider,
      proofProvider: { proveTx: edges.proveTx ?? (async (tx: unknown) => tx) } as unknown as Publisher["proofProvider"],
      compiledContract,
      verifierKeys: edges.verifierKeys ?? realVerifierKeys,
    } as unknown as Publisher),
  );
}

const PRODUCTION_TIMEOUT = RESPOND_TIMEOUT.ms;

afterEach(async () => {
  await closePublisher();
  RESPOND_TIMEOUT.ms = PRODUCTION_TIMEOUT;
});

describe("withDeadline", () => {
  it("passes a timely result through", async () => {
    await expect(withDeadline(Promise.resolve(7), 1_000, () => new Error("never"))).resolves.toBe(7);
  });

  it("rejects with the factory's error once the deadline passes", async () => {
    const hang = new Promise<never>(() => undefined);
    const timeout = withDeadline(hang, 20, () => new PublisherError("internal", "took too long"));
    await expect(timeout).rejects.toMatchObject({ code: "internal" });
  });

  it("leaves the abandoned attempt's late failure handled", async () => {
    // An unhandled rejection from the losing side would kill a process holding a
    // hot wallet; `Promise.race` is what makes it not one.
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

function skewedContractState(): Uint8Array {
  const real = Buffer.from(readFileSync(`${FIXTURES}respond-singleton-state-37571.mn`));
  const offset = real.indexOf("midnight:contract-state[v") + "midnight:contract-state[v".length;
  const skewed = Uint8Array.from(real);
  skewed[offset] = "9".charCodeAt(0);
  return skewed;
}

// The library's own error, never a hand-built stand-in.
function thrownBy(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    return error;
  }
  throw new Error("expected a throw");
}

describe("POST /respond: the flow against stubbed edges", () => {
  it("names the read failure when the node read fails", async () => {
    primeStub();
    const client = stubClient({ head: async () => Promise.reject(new Error("socket dropped")) });
    const reply = await handleRespond(TEST_CONFIG, client, respondBody("cd".repeat(32)));
    expect(reply.status).toBe(502);
    expect(parseBody(reply)).toMatchObject({ code: "node_unavailable" });
  });

  it("answers contract_absent when the address has no state", async () => {
    primeStub();
    const client = stubClient({ contract: async () => runtimeError });
    const reply = await handleRespond(TEST_CONFIG, client, respondBody("cd".repeat(32)));
    expect(reply.status).toBe(409);
    expect(parseBody(reply)).toMatchObject({ code: "contract_absent" });
    expect(parseBody(reply)["message"]).toContain(SINGLETON);
  });

  it("answers contract_mismatch when the deployed keys are not this build's", async () => {
    // An EMPTY key list passes vacuously, so the wrongness has to be real: pair
    // each circuit with the other's key, which is what a stale `managedDir` looks like.
    const [first, second, ...rest] = realVerifierKeys;
    if (first === undefined || second === undefined) throw new Error("the contract ships at least two circuits");
    primeStub({ verifierKeys: [[first[0], second[1]], [second[0], first[1]], ...rest] });
    const reply = await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32)));
    expect(reply.status).toBe(409);
    expect(parseBody(reply)).toMatchObject({ code: "contract_mismatch" });
    expect(parseBody(reply)["message"]).toContain("MIDNIGHT_PUB_MANAGED_DIR");
  });

  it("carries the proof provider's output through balance and into submit", async () => {
    // The wallet stubs are identity functions, so only a sentinel notices the
    // proven transaction being dropped for the unproven one.
    const proven = { proven: true };
    let balanced: unknown;
    let submitted: unknown;
    primeStub({
      proveTx: async () => proven,
      balanceTx: async (tx) => {
        balanced = tx;
        return tx;
      },
      submitTx: async (tx) => {
        submitted = tx;
        return "ab".repeat(32);
      },
    });
    expect((await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32)))).status).toBe(200);
    expect(balanced).toBe(proven);
    expect(submitted).toBe(proven);
  });

  it("names prove_failed when the proof server refuses", async () => {
    // Reaching this stage at all means the circuit really ran against the fixture state.
    primeStub({ proveTx: async () => Promise.reject(new Error("proof server refused")) });
    const reply = await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32)));
    expect(reply.status).toBe(502);
    expect(parseBody(reply)).toMatchObject({ code: "prove_failed" });
  });

  it("rejects an untagged read before the deserializer sees it", async () => {
    // Why the tag check carries a hint: the deserializer would only say "malformed".
    primeStub();
    const reply = await handleRespond(
      TEST_CONFIG,
      stubClient({ zswap: async () => ok(Uint8Array.of(1, 2, 3)) }),
      respondBody("cd".repeat(32)),
    );
    expect(parseBody(reply)).toMatchObject({ code: "ledger_mismatch" });
    expect(parseBody(reply)["message"]).toContain("0x-prefixed hex");
  });

  it("names a dependency's ledger skew rather than the step it surfaced in", async () => {
    // A skew past the tag checks came out of a dependency's own blob, and
    // `prove_failed` would send the operator to the proof server's logic instead.
    const skew = thrownBy(() => deserializeCompactContractState(skewedContractState(), { caller: "test" }));
    primeStub({ proveTx: async () => Promise.reject(skew) });
    const reply = await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32)));
    expect(parseBody(reply)).toMatchObject({ code: "ledger_mismatch" });
  });

  it("keeps a merely malformed blob at the step that produced it", async () => {
    // Why the guard is on the received version: the library calls this
    // `version-mismatch` too, meaning only "these bytes are not a contract state".
    const corrupt = Uint8Array.from(skewedContractState());
    corrupt[0] = 0;
    const malformed = thrownBy(() => deserializeCompactContractState(corrupt, { caller: "test" }));
    primeStub({ proveTx: async () => Promise.reject(malformed) });
    const reply = await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32)));
    expect(parseBody(reply)).toMatchObject({ code: "prove_failed" });
  });

  it("keeps balance_failed and submit_rejected apart", async () => {
    primeStub({ balanceTx: async () => Promise.reject(new Error("dust actions rejected")) });
    expect(parseBody(await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32))))).toMatchObject({
      code: "balance_failed",
    });
  });

  it("names submit_rejected when the chain refuses the balanced transaction", async () => {
    primeStub({ submitTx: async () => Promise.reject(new Error("transaction rejected")) });
    expect(parseBody(await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32))))).toMatchObject({
      code: "submit_rejected",
    });
  });

  it("refines a dust shortfall into wallet_unfunded", async () => {
    primeStub({ balanceTx: async () => Promise.reject(new Error("Wallet.InsufficientFunds: could not balance dust")) });
    const reply = await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32)));
    expect(reply.status).toBe(503);
    expect(parseBody(reply)).toMatchObject({ code: "wallet_unfunded" });
  });

  it("refines an optimistic-concurrency loss into state_conflict", async () => {
    primeStub({ submitTx: async () => Promise.reject(new Error("Transcript(Execution(ReadMismatch { expected: 06 }))")) });
    const reply = await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32)));
    expect(reply.status).toBe(409);
    expect(parseBody(reply)).toMatchObject({ code: "state_conflict" });
  });

  it("logs the rendered cause chain when Effect flattens the message", async () => {
    // Every node error is wrapped in a constant-message SubmissionError whose
    // cause Effect stores on a Symbol, out of `describeFailure`'s reach, so the
    // chain that proves the classification has to survive in the log.
    const logged: unknown[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((line: unknown) => void logged.push(line));
    class SubmissionError extends Data.TaggedError("SubmissionError")<{ message: string; cause?: unknown }> {}
    class TransactionInvalidError extends Data.TaggedError("TransactionInvalidError")<{ message: string }> {}
    primeStub({
      submitTx: () =>
        Effect.runPromise(
          Effect.fail(
            new SubmissionError({
              message: "Transaction submission error",
              cause: new TransactionInvalidError({ message: "rejected by the node: Transcript(Execution(ReadMismatch))" }),
            }),
          ),
        ) as Promise<string>,
    });
    const reply = await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32)));
    spy.mockRestore();
    expect(reply.status).toBe(409);
    const body = parseBody(reply);
    expect(body).toEqual({ code: "state_conflict", message: expect.stringContaining("Transaction submission error") });
    expect(logged.join("\n")).toContain("ReadMismatch");
  });

  it("plumbs a boot failure's code out to the wire", async () => {
    primePublisher(Promise.reject(new PublisherError("wallet_unsynced", "the funding wallet could not sync")));
    const reply = await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32)));
    expect(reply.status).toBe(503);
    expect(parseBody(reply)).toMatchObject({ code: "wallet_unsynced" });
  });
});

describe("POST /respond: the busy gate", () => {
  it("does not let a rejected request leave the gate claimed", async () => {
    primeStub();
    const failing = stubClient({ head: async () => Promise.reject(new Error("boom")) });
    expect((await handleRespond(TEST_CONFIG, failing, respondBody("aa".repeat(32)))).status).toBe(502);
    expect((await handleRespond(TEST_CONFIG, stubClient(), respondBody("bb".repeat(32)))).status).toBe(200);
  });

  it("keeps the gate claimed while an abandoned post is still running", async () => {
    // Releasing on the answer would admit a second post onto the one dust UTXO
    // the first has not finished with. The process stops instead.
    primeStub();
    RESPOND_TIMEOUT.ms = 50;
    const hung = stubClient({ head: () => new Promise(() => undefined) });
    expect((await handleRespond(TEST_CONFIG, hung, respondBody("aa".repeat(32)))).status).toBe(500);

    RESPOND_TIMEOUT.ms = PRODUCTION_TIMEOUT;
    const refused = await handleRespond(TEST_CONFIG, stubClient(), respondBody("bb".repeat(32)));
    expect(refused.status).toBe(503);
    expect(parseBody(refused)).toMatchObject({ code: "wallet_busy" });
    expect(parseBody(refused)["message"]).toContain("aa".repeat(32));
  });

  it("never lets two posts balance at once, even across a blown deadline", async () => {
    // The invariant the gate is FOR, measured rather than argued.
    let live = 0;
    let peak = 0;
    const slowBalance = async (tx: unknown): Promise<unknown> => {
      live += 1;
      peak = Math.max(peak, live);
      await new Promise((resolve) => setTimeout(resolve, 300));
      live -= 1;
      return tx;
    };
    primeStub({ balanceTx: slowBalance });
    RESPOND_TIMEOUT.ms = 100;
    expect((await handleRespond(TEST_CONFIG, stubClient(), respondBody("aa".repeat(32)))).status).toBe(500);

    RESPOND_TIMEOUT.ms = PRODUCTION_TIMEOUT;
    await handleRespond(TEST_CONFIG, stubClient(), respondBody("bb".repeat(32)));
    expect(peak).toBe(1);
    await new Promise((resolve) => setTimeout(resolve, 400));
  });

  it("never claims the gate for a request that fails validation", async () => {
    primeStub();
    expect((await handleRespond(TEST_CONFIG, stubClient(), "{")).status).toBe(400);
    expect((await handleRespond(TEST_CONFIG, stubClient(), respondBody("dd".repeat(32)))).status).toBe(200);
  });
});

// This is the one route that spends money, so it is the last that should be reached only in process.
describe("POST /respond: over the real HTTP server", () => {
  it("routes, answers 200, and carries the wire body as JSON", async () => {
    primeStub({ submitTx: async () => "cafe".repeat(16) });
    const server = await listening(TEST_CONFIG, stubClient());
    try {
      const answer = await server.send("/respond", { method: "POST", body: respondBody("cd".repeat(32)) });
      expect(answer.status).toBe(200);
      expect(JSON.parse(answer.body)).toEqual({ status: "ok", tx_id: "cafe".repeat(16), block_hash: HEAD_BARE });
      expect(answer.contentType).toBe("application/json");
    } finally {
      server.close();
    }
  });

  it("answers a blown deadline first, and only then stops the process", async () => {
    // Stopping before the reply is flushed would leave the caller with a dropped
    // connection and no way to learn its post may still land.
    primeStub();
    RESPOND_TIMEOUT.ms = 50;
    let stop!: () => void;
    const stopped = new Promise<void>((resolve) => {
      stop = resolve;
    });
    const rid = "cd".repeat(32);
    const hung = stubClient({ head: () => new Promise(() => undefined) });
    const server = await listening(TEST_CONFIG, hung, stop);
    try {
      const answer = await server.send("/respond", { method: "POST", body: respondBody(rid) });
      expect(answer.status).toBe(500);
      expect(parseBody(answer)).toMatchObject({ code: "internal" });
      expect(parseBody(answer)["message"]).toMatch(/deadline/);
      expect(parseBody(answer)["message"]).toContain(rid);
      expect(parseBody(answer)["message"]).toMatch(/may still land/);
      await stopped;
    } finally {
      server.close();
    }
  });

  it("does not stop the process for an ordinary failure", async () => {
    primeStub();
    let stops = 0;
    const failing = stubClient({ head: async () => Promise.reject(new Error("socket dropped")) });
    const server = await listening(TEST_CONFIG, failing, () => (stops += 1));
    try {
      expect((await server.send("/respond", { method: "POST", body: respondBody("cd".repeat(32)) })).status).toBe(502);
      expect(stops).toBe(0);
    } finally {
      server.close();
    }
  });

  it("maps a rejected body to 400 through the route, not just through the handler", async () => {
    primeStub();
    const server = await listening(TEST_CONFIG, stubClient());
    try {
      const answer = await server.send("/respond", { method: "POST", body: "{" });
      expect(answer.status).toBe(400);
      expect(parseBody(answer)).toMatchObject({ code: "bad_request" });
      expect(answer.contentType).toBe("application/json");
    } finally {
      server.close();
    }
  });

  it("refuses a second concurrent post with 503 wallet_busy, on one server", async () => {
    // A real second connection must be answered while the first still holds the wallet.
    primeStub();
    let releaseHead: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      releaseHead = () => resolve();
    });
    const gated = stubClient({
      head: async () => {
        await gate;
        return { toHex: () => `0x${HEAD_BARE}` };
      },
    });
    const server = await listening(TEST_CONFIG, gated);
    try {
      const first = server.send("/respond", { method: "POST", body: respondBody("aa".repeat(32)) });
      await new Promise((resolve) => setTimeout(resolve, 10));

      const second = await server.send("/respond", { method: "POST", body: respondBody("bb".repeat(32)) });
      expect(second.status).toBe(503);
      expect(parseBody(second)).toMatchObject({ code: "wallet_busy" });
      expect(parseBody(second)["message"]).toContain("aa".repeat(32));

      releaseHead?.();
      expect((await first).status).toBe(200);

      // Released by COMPLETION: a gate that only opens on the error path strands
      // the wallet after the first successful post.
      const third = await server.send("/respond", { method: "POST", body: respondBody("cc".repeat(32)) });
      expect(third.status).toBe(200);
    } finally {
      server.close();
    }
  });
});
