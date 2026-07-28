// The wire, end to end: a request line in, a reply line out, against the real
// compiled contract and the real captured singleton. `handleLine` is the whole
// process minus stdin, so what passes here is what the Rust client will see.

import { afterEach, describe, expect, it } from "vitest";

import { LedgerParameters } from "@midnightntwrk/ledger-v9";
import { ContractState } from "@midnight-ntwrk/compact-runtime";

import { handleLine } from "../src/protocol.js";
import { closePublisher, primePublisher, type Publisher } from "../src/submit.js";
import type { FundingWallet } from "../src/wallet.js";
import { fixtureBytes, pushedCallArgs, testConfig, toHex } from "./support.js";

const CONFIG = testConfig();

// Same singleton and request id as the intent tests: the state fixture carries the
// verifier keys the entry-point lookup matches against.
const SINGLETON = "d7b3c45da613be25050bbdf3fde4cef8f66154d3a52ca8c1edd878bd6391f169";
const REQUEST_ID = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";

// All different, so a field that arrives in the wrong slot cannot look correct.
const X = "11".repeat(32);
const Y = "22".repeat(32);
const S = "33".repeat(32);

const request = (overrides: Record<string, unknown> = {}): string =>
  JSON.stringify({
    id: 7,
    circuit: "respond",
    contractAddress: SINGLETON,
    requestId: REQUEST_ID,
    signature: { bigR: { x: X, y: Y }, s: S, recoveryId: 0 },
    contractState: toHex(fixtureBytes("respond-singleton-state-37571.mn")),
    ledgerParameters: toHex(LedgerParameters.initialParameters().serialize()),
    coinPublicKey: "44".repeat(32),
    ttlSeconds: 1_800_000_000,
    ...overrides,
  });

const answer = async (line: string) => JSON.parse(await handleLine(CONFIG, line));

// The submit half's paid edges, so the round trip below exercises the wire and not the
// chain. Everything before them, including the transaction the intent becomes, is real.
const TX_ID = "ab".repeat(32);
const BLOCK_HASH = "cd".repeat(32);

function primeStub(): void {
  primePublisher(
    Promise.resolve({
      proveTx: async (tx: unknown) => tx,
      wallet: {
        balanceTx: async (tx: unknown) => tx,
        finalizeTx: async (recipe: unknown) => recipe,
        submitTx: async () => ({ txId: TX_ID, blockHash: BLOCK_HASH }),
        close: async () => undefined,
      } as unknown as FundingWallet,
    } as unknown as Publisher),
  );
}

afterEach(() => closePublisher());

describe("handleLine", () => {
  it("answers a valid request with hex intent bytes and the same id", async () => {
    const reply = await answer(request());

    expect(reply.id).toBe(7);
    expect(reply.ok).toBe(true);
    expect(reply.intent).toMatch(/^(?:[0-9a-f]{2})+$/);
  });

  it("answers a line, never a fragment: a reply carries no raw newline", async () => {
    // stdout is the wire and `main.ts` frames it with "\n", so a reply holding one
    // would split into two unparseable halves at the reader.
    expect(await handleLine(CONFIG, request())).not.toContain("\n");
    expect(await handleLine(CONFIG, "{not json")).not.toContain("\n");
  });

  it("carries the intent the ledger's own tagged reader accepts", async () => {
    const reply = await answer(request());

    expect(Buffer.from(reply.intent, "hex").subarray(0, 20).toString("utf8")).toContain("midnight:intent[v9]");
  });

  it("delivers the wire's own signature to the circuit, in the wire's own order", async () => {
    // Field names cross the wire as strings, so nothing but this checks that the JSON
    // `signature.bigR.x` is the value the circuit received as x. The type system pins
    // the names; only the decoded call pins the values.
    const reply = await answer(request());

    expect(pushedCallArgs(Buffer.from(reply.intent, "hex"))).toBe(`pushs <[${X}, ${Y}, ${S}, -]: b32b32b32b1>`);
  });

  it("builds respondBidirectional with its output and length", async () => {
    const output = "ab".repeat(128);
    const reply = await answer(request({ circuit: "respondBidirectional", serializedOutput: output, outputLen: 32 }));

    expect(reply.ok).toBe(true);
    expect(reply.intent).toMatch(/^(?:[0-9a-f]{2})+$/);
    // 0x20, the wire's 32: the length has to survive the crossing as a number, not as
    // whatever a dropped field would default to.
    expect(pushedCallArgs(Buffer.from(reply.intent, "hex"))).toBe(
      `pushs <[${output}, 20, ${X}, ${Y}, ${S}, -]: b128b1b32b32b32b1>`,
    );
  });

  it("answers unparseable JSON with an error line rather than throwing", async () => {
    const reply = await answer("{not json");

    expect(reply.ok).toBe(false);
    expect(reply.code).toBe("bad_request");
  });

  it("rejects a JSON array, which parses but is not a request", async () => {
    const reply = await answer("[]");

    expect(reply).toMatchObject({ ok: false, code: "bad_request" });
  });

  it("echoes the id even when the request is rejected, so a caller can fail the right post", async () => {
    expect(await answer(JSON.stringify({ id: 9, circuit: "nope" }))).toMatchObject({ id: 9, ok: false });
  });

  it("answers a null id when the line carried none, rather than inventing one", async () => {
    expect(await answer("{not json")).toMatchObject({ id: null });
    expect(await answer(JSON.stringify({ id: "7", circuit: "respond" }))).toMatchObject({ id: null });
  });

  it("names the offending field in a rejection", async () => {
    const cases: readonly [Record<string, unknown>, string][] = [
      [{ coinPublicKey: undefined }, "coinPublicKey"],
      [{ contractAddress: "00" }, "contractAddress"],
      [{ signature: { bigR: { x: "11".repeat(32) }, s: "33".repeat(32), recoveryId: 0 } }, "signature.bigR.y"],
      [{ ttlSeconds: 0 }, "ttlSeconds"],
      [{ contractAddress: "AB".repeat(32) }, "contractAddress"],
      [{ contractState: "ZZ" }, "contractState"],
      // `Buffer.from` truncates an odd digit silently, so the schema is the only thing between
      // a mistyped blob and a deserializer failing on bytes nobody sent.
      [{ ledgerParameters: "abc" }, "ledgerParameters"],
      [{ circuit: "respondBidirectional", serializedOutput: "ab".repeat(128), outputLen: 129 }, "outputLen"],
      [{ circuit: "respondBidirectional", serializedOutput: "ab".repeat(127), outputLen: 0 }, "serializedOutput"],
    ];

    for (const [override, field] of cases) {
      const reply = await answer(request(override));
      expect(reply, field).toMatchObject({ id: 7, ok: false, code: "bad_request" });
      expect(reply.message).toContain(field);
    }
  });

  it("reports the FIRST invalid field in declaration order, which is what makes that order a contract", async () => {
    // Only one issue is ever surfaced, so reordering the schema silently changes which
    // failure a caller is told about. Two bad fields at once is the only way to see it.
    const both = await answer(request({ contractAddress: "00", requestId: "00" }));
    expect(both.message).toContain("contractAddress");
    expect(both.message).not.toContain("requestId");

    // And `id` outranks everything, so a reply can always name its post.
    const withBadId = await answer(request({ id: 1.5, contractAddress: "00" }));
    expect(withBadId.message).toContain("`id`");
    expect(withBadId.message).not.toContain("contractAddress");
  });

  it("rejects an id JSON cannot round-trip, rather than echoing a different one", async () => {
    // 2^53+1 parses to 2^53, so echoing it would answer a post the caller never sent.
    // The Rust client has to keep its ids below 2^53 for the same reason.
    const tooBig = await answer(request().replace('"id":7', '"id":9007199254740993'));
    expect(tooBig).toMatchObject({ id: null, ok: false, code: "bad_request" });
    expect(tooBig.message).toContain("`id`");

    expect(await answer(request({ id: -1 }))).toMatchObject({ id: -1, ok: false, code: "bad_request" });
  });

  it("rejects a signature whose recovery id is neither 0 nor 1", async () => {
    const signature = { bigR: { x: "11".repeat(32), y: "22".repeat(32) }, s: "33".repeat(32), recoveryId: 2 };

    expect(await answer(request({ signature }))).toMatchObject({ ok: false, code: "bad_request" });
  });

  it("surfaces a builder failure as its own code, not as a throw", async () => {
    // A managed dir pointed at a different build than what is deployed reaches the
    // caller by name. Stands in here as a contract with no operations at all.
    const reply = await answer(request({ contractState: toHex(new ContractState().serialize()) }));

    expect(reply).toMatchObject({ id: 7, ok: false, code: "contract_mismatch" });
    expect(reply.message).toContain("respond");
  });

  it("answers `internal` when the request is well formed but the bytes are not", async () => {
    // Valid hex of the wrong thing: the failure comes out of the ledger's own
    // deserializer, so it is ours to classify rather than the caller's to fix.
    const reply = await answer(request({ contractState: "00".repeat(64) }));

    expect(reply).toMatchObject({ id: 7, ok: false, code: "internal" });
    expect(reply.message.length).toBeGreaterThan(0);
  });
});

// Two operations on one wire. `op` is optional and absent means `build`, which is the
// only reason the request above still parses.
describe("handleLine: the operation discriminator", () => {
  it("treats an absent op and an explicit build as the same request", async () => {
    const implicit = await answer(request());
    const explicit = await answer(request({ op: "build" }));

    expect(implicit).toMatchObject({ id: 7, ok: true });
    expect(explicit).toMatchObject({ id: 7, ok: true });
  });

  it("names `op` when it is neither, rather than reporting a missing circuit", async () => {
    // A request with an unknown op has no `circuit` either; blaming that would send the
    // caller looking at the wrong field.
    const reply = await answer(JSON.stringify({ id: 7, op: "publish", intent: "00" }));

    expect(reply).toMatchObject({ id: 7, ok: false, code: "bad_request" });
    expect(reply.message).toContain("`op`");
  });

  it("round-trips a submit's id alongside the transaction id and the block it landed in", async () => {
    primeStub();
    const built = await answer(request());

    const reply = await answer(JSON.stringify({ id: 21, op: "submit", intent: built.intent }));

    expect(reply).toEqual({ id: 21, ok: true, txId: TX_ID, blockHash: BLOCK_HASH });
  });

  it("names `intent` when it is not the hex the wire admits", async () => {
    const cases = ["", "abc", "ZZ", "AB".repeat(32), null, 7];

    for (const intent of cases) {
      const reply = await answer(JSON.stringify({ id: 22, op: "submit", intent }));
      expect(reply, String(intent)).toMatchObject({ id: 22, ok: false, code: "bad_request" });
      expect(reply.message).toContain("intent");
    }
  });

  it("names `intent` when the hex is fine and the bytes are not an intent", async () => {
    const reply = await answer(JSON.stringify({ id: 23, op: "submit", intent: "00".repeat(64) }));

    expect(reply).toMatchObject({ id: 23, ok: false, code: "bad_request" });
    expect(reply.message).toContain("`intent`");
  });

  it("refuses a submit on a deployment that only builds, naming what to configure", async () => {
    // `testConfig` carries no endpoints, which is the indexer-only deployment.
    const built = await answer(request());

    const reply = await answer(JSON.stringify({ id: 24, op: "submit", intent: built.intent }));

    expect(reply).toMatchObject({ id: 24, ok: false, code: "wallet_unsynced" });
    expect(reply.message).toContain("MIDNIGHT_PUB_NODE_URL");
  });
});
