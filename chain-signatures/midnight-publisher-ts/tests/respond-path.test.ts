/**
 * `POST /respond` orchestration tests, offline.
 *
 * The write path used to have no offline coverage past the `bad_request`
 * branch: everything else needed a live stack. This file closes the
 * ORCHESTRATION half of that gap: a stub node client whose runtime API serves
 * captured fixture blobs, and a publisher primed through the test seam from the
 * real compiled-contract assets, real derived keys, and stub proof and wallet
 * edges. The circuit itself really runs (`createUnprovenCallTxFromInitialStates`
 * executes the compact-generated JavaScript against the fixture state), so what
 * these tests prove is the flow: staging, deadlines, the busy gate, error
 * classification, and the success wire shape.
 *
 * Deliberately NOT covered here, and covered by `tests/respond-live.ts`
 * instead: the real wallet facade, real proving, and real submission.
 */

import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";

import { LedgerParameters, ZswapChainState } from "@midnightntwrk/ledger-v9";
import { ContractExecutable } from "@midnight-ntwrk/midnight-js-protocol/compact-js";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import { setNetworkId } from "@midnight-ntwrk/midnight-js/network-id";
import {
  Contract as SignetContract,
  type SignetContractCircuitId,
  type SignetContractPrivateState,
} from "@sig-net/midnight-contract";
import { makeVacantCompiledContract } from "@sig-net/midnight-contract-deploy";
import { Data, Effect } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import type { Config } from "../src/config.js";
import { PublisherError, type Reply } from "../src/errors.js";
import type { NodeClient } from "../src/node.js";
import {
  closePublisher,
  handleRespond,
  primePublisher,
  RESPOND_DEADLINES,
  withDeadline,
  type Publisher,
} from "../src/respond.js";
import { deriveFundingKeys, type FundingWallet } from "../src/wallet.js";

const FIXTURES = fileURLToPath(new URL("./fixtures/", import.meta.url));
const MANAGED = fileURLToPath(new URL("../node_modules/@sig-net/midnight-contract/dist/managed/", import.meta.url));

/** The deployed singleton the state fixture was captured from. */
const SINGLETON = "82ebe184cd00e19e422f0e7aa246012e11160ba3b98c09aace67dab1664af182";

/** The public genesis dev seed, as in `tests/respond-live.ts`. Not a secret. */
const DEV_SEED = "0000000000000000000000000000000000000000000000000000000000000001";

/** The finalized head every stub client pins, bare and `0x`-prefixed. */
const HEAD_BARE = "ab".repeat(32);

const TEST_CONFIG: Config = {
  port: 0,
  bindHost: "127.0.0.1",
  nodeUrl: "ws://127.0.0.1:1",
  proofServerUrl: "http://127.0.0.1:1",
  indexerUrl: "http://127.0.0.1:1",
  indexerWsUrl: "ws://127.0.0.1:1",
  managedDir: MANAGED,
  fundingSeed: DEV_SEED,
  networkId: "undeployed",
};

/** A valid `postSignatureResponse` body; the circuit is a blind append, so any 32-byte values do. */
function respondBody(rid: string): string {
  return JSON.stringify({
    contract_address: SINGLETON,
    circuit: "postSignatureResponse",
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

// ---- the stub node client ----------------------------------------------------

type RuntimeResult = { isOk: boolean; asOk: { toU8a: (bare?: boolean) => Uint8Array } };

const ok = (bytes: Uint8Array): RuntimeResult => ({ isOk: true, asOk: { toU8a: () => bytes } });
const runtimeError: RuntimeResult = { isOk: false, asOk: { toU8a: () => Uint8Array.of() } };

interface StubReads {
  readonly head?: () => Promise<{ toHex: () => string }>;
  readonly contract?: () => Promise<RuntimeResult>;
  readonly zswap?: () => Promise<RuntimeResult>;
  readonly params?: () => Promise<RuntimeResult>;
}

/**
 * The shape `readCallStates` actually touches, backed by the captured contract
 * state and freshly serialized (hence correctly tagged) zswap and parameter
 * blobs. Everything else on the client is unreachable by construction.
 */
function stubClient(overrides: StubReads = {}): NodeClient {
  const reads: Required<StubReads> = {
    head: async () => ({ toHex: () => `0x${HEAD_BARE}` }),
    contract: async () => ok(Uint8Array.from(readFileSync(`${FIXTURES}respond-singleton-state-25087.mn`))),
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

// ---- the primed publisher ------------------------------------------------------

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
  // The transaction under construction bakes the network id into address
  // encoding; `buildPublisher` normally does this and the seam bypasses it.
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

/** Real assets and keys, stubbed proof and wallet edges; installed via the test seam. */
function primeStub(edges: StubEdges = {}): void {
  const keys = deriveFundingKeys(DEV_SEED, TEST_CONFIG.networkId);
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

afterEach(async () => {
  await closePublisher();
  RESPOND_DEADLINES.boot = 90_000;
  RESPOND_DEADLINES.read = 15_000;
  RESPOND_DEADLINES.prove = 60_000;
});

// ---- withDeadline --------------------------------------------------------------

describe("withDeadline", () => {
  it("passes a timely result through", async () => {
    await expect(withDeadline(Promise.resolve(7), 1_000, () => new Error("never"))).resolves.toBe(7);
  });

  it("rejects with the factory's error once the deadline passes", async () => {
    const hang = new Promise<never>(() => undefined);
    const timeout = withDeadline(hang, 20, () => new PublisherError("wallet_unsynced", "took too long", "boot"));
    await expect(timeout).rejects.toMatchObject({ code: "wallet_unsynced", stage: "boot" });
  });

  it("names the operation and the budget in the plain-string form", async () => {
    const hang = new Promise<never>(() => undefined);
    await expect(withDeadline(hang, 20, "proving")).rejects.toThrow("proving exceeded the 20 ms deadline");
  });

  it("swallows the abandoned attempt's late failure", async () => {
    // The losing side of the race may still reject; that must not surface as an
    // unhandled rejection after the caller already got its answer.
    const late = new Promise<never>((_, reject) => setTimeout(() => reject(new Error("late")), 20));
    await expect(withDeadline(late, 5, () => new Error("deadline"))).rejects.toThrow("deadline");
    await new Promise((resolve) => setTimeout(resolve, 40));
  });
});

// ---- the respond flow, stage by stage -------------------------------------------

describe("POST /respond: the flow against stubbed edges", () => {
  it("answers ok with the tx id and the pinned block hash", async () => {
    primeStub({ submitTx: async () => "cafe".repeat(16) });
    const reply = await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32)));
    expect(reply.status).toBe(200);
    // `block_hash` is bare hex, the integration's address/atom convention, and
    // is the block the three reads were pinned to — the caller's anchor for
    // settlement observation.
    expect(parseBody(reply)).toEqual({
      status: "ok",
      tx_id: "cafe".repeat(16),
      block_hash: HEAD_BARE,
    });
  });

  it("names the read stage when the node read fails", async () => {
    primeStub();
    const client = stubClient({ head: async () => Promise.reject(new Error("socket dropped")) });
    const reply = await handleRespond(TEST_CONFIG, client, respondBody("cd".repeat(32)));
    expect(reply.status).toBe(502);
    expect(parseBody(reply)).toMatchObject({ code: "node_unavailable", stage: "read" });
  });

  it("converts a hung node read into node_unavailable instead of never answering", async () => {
    // THE dead-dependency conversion: `@polkadot/api` queues calls forever
    // across reconnects, so without the deadline this request simply hangs.
    primeStub();
    RESPOND_DEADLINES.read = 50;
    const client = stubClient({ head: () => new Promise(() => undefined) });
    const reply = await handleRespond(TEST_CONFIG, client, respondBody("cd".repeat(32)));
    expect(reply.status).toBe(502);
    expect(parseBody(reply)).toMatchObject({ code: "node_unavailable", stage: "read" });
    expect(parseBody(reply)["message"]).toMatch(/deadline/);
  });

  it("answers contract_absent, staged, when the address has no state", async () => {
    primeStub();
    const client = stubClient({ contract: async () => runtimeError });
    const reply = await handleRespond(TEST_CONFIG, client, respondBody("cd".repeat(32)));
    expect(reply.status).toBe(409);
    expect(parseBody(reply)).toMatchObject({ code: "contract_absent", stage: "read" });
    expect(parseBody(reply)["message"]).toContain(SINGLETON);
  });

  it("answers contract_mismatch when the deployed keys are not this build's", async () => {
    // An EMPTY key list passes vacuously (nothing claimed, nothing checked), so
    // the wrongness has to be real: pair each of two circuits with the other's
    // key. This is exactly what a stale `managedDir` looks like.
    const [first, second, ...rest] = realVerifierKeys;
    if (first === undefined || second === undefined) throw new Error("the contract ships at least two circuits");
    primeStub({ verifierKeys: [[first[0], second[1]], [second[0], first[1]], ...rest] });
    const reply = await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32)));
    expect(reply.status).toBe(409);
    expect(parseBody(reply)).toMatchObject({ code: "contract_mismatch" });
    expect(parseBody(reply)["message"]).toContain("MIDNIGHT_PUB_MANAGED_DIR");
  });

  it("names the prove stage when the proof server refuses", async () => {
    // Reaching this stage at all means the circuit really ran: the unproven
    // transaction was built from the fixture state before the stub refused it.
    primeStub({ proveTx: async () => Promise.reject(new Error("proof server refused")) });
    const reply = await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32)));
    expect(reply.status).toBe(502);
    expect(parseBody(reply)).toMatchObject({ code: "prove_failed", stage: "prove" });
  });

  it("refines the balance stage's dust shortfall into wallet_unfunded", async () => {
    primeStub({ balanceTx: async () => Promise.reject(new Error("Wallet.InsufficientFunds: could not balance dust")) });
    const reply = await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32)));
    expect(reply.status).toBe(503);
    expect(parseBody(reply)).toMatchObject({ code: "wallet_unfunded", stage: "balance" });
  });

  it("refines the submit stage's optimistic-concurrency loss into state_conflict", async () => {
    primeStub({ submitTx: async () => Promise.reject(new Error("Transcript(Execution(ReadMismatch { expected: 06 }))")) });
    const reply = await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32)));
    expect(reply.status).toBe(409);
    expect(parseBody(reply)).toMatchObject({ code: "state_conflict", stage: "submit" });
  });

  it("forwards the rendered cause chain as detail when Effect flattens the message", async () => {
    // The submission service wraps every node error in a constant-message
    // SubmissionError whose cause Effect stores on a Symbol, out of
    // `describeFailure`'s reach. The caller must still receive the evidence:
    // classification alone could be wrong, and the chain is what proves it.
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
    expect(reply.status).toBe(409);
    const body = parseBody(reply);
    expect(body).toMatchObject({ code: "state_conflict", stage: "submit" });
    expect(String(body["message"])).toContain("Transaction submission error");
    expect(String(body["detail"])).toContain("ReadMismatch");
    expect(String(body["detail"])).not.toMatch(/^\s+at /m);
  });

  it("plumbs a boot failure's code and stage out to the wire", async () => {
    // The deadline that MAKES boot fail this way is unit-tested above; this
    // pins the rest of the trip: code, status, and stage reach the caller.
    primePublisher(Promise.reject(new PublisherError("wallet_unsynced", "publisher boot exceeded 90000 ms", "boot")));
    const reply = await handleRespond(TEST_CONFIG, stubClient(), respondBody("cd".repeat(32)));
    expect(reply.status).toBe(503);
    expect(parseBody(reply)).toMatchObject({ code: "wallet_unsynced", stage: "boot" });
  });
});

// ---- one at a time ---------------------------------------------------------------

describe("POST /respond: the busy gate", () => {
  it("answers wallet_busy while another rid holds the wallet, then admits again", async () => {
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

    const first = handleRespond(TEST_CONFIG, gated, respondBody("aa".repeat(32)));
    await new Promise((resolve) => setTimeout(resolve, 10));

    // The second post is refused up front: without the gate it could only burn
    // a prove and fail at balance ~35 seconds of dust recovery later.
    const second = await handleRespond(TEST_CONFIG, stubClient(), respondBody("bb".repeat(32)));
    expect(second.status).toBe(503);
    expect(parseBody(second)).toMatchObject({ code: "wallet_busy" });
    expect(parseBody(second)["message"]).toContain("aa".repeat(32));

    releaseHead?.();
    expect((await first).status).toBe(200);

    // The slot is released by completion, success and failure alike.
    const third = await handleRespond(TEST_CONFIG, stubClient(), respondBody("cc".repeat(32)));
    expect(third.status).toBe(200);
  });

  it("does not let a rejected request leave the gate claimed", async () => {
    primeStub();
    const failing = stubClient({ head: async () => Promise.reject(new Error("boom")) });
    expect((await handleRespond(TEST_CONFIG, failing, respondBody("aa".repeat(32)))).status).toBe(502);
    expect((await handleRespond(TEST_CONFIG, stubClient(), respondBody("bb".repeat(32)))).status).toBe(200);
  });

  it("never claims the gate for a request that fails validation", async () => {
    primeStub();
    expect((await handleRespond(TEST_CONFIG, stubClient(), "{")).status).toBe(400);
    expect((await handleRespond(TEST_CONFIG, stubClient(), respondBody("dd".repeat(32)))).status).toBe(200);
  });
});
