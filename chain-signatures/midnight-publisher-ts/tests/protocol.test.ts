// The wire end to end: `handleLine` is the whole process minus stdin, so what passes
// here is what the Rust client will see.

import { readFileSync } from "node:fs";

import { afterEach, describe, expect, it } from "vitest";

import { LedgerParameters } from "@midnightntwrk/ledger-v9";
import { ContractState } from "@midnight-ntwrk/compact-runtime";

import { handleLine } from "../src/protocol.js";
import { closePublisher } from "../src/submit.js";
import {
  calledEntryPoint,
  initialSingletonStateHex,
  primeStub,
  pushedCallArgs,
  STUB_BLOCK_HASH,
  STUB_TX_ID,
  testConfig,
  toHex,
} from "./support.js";

const CONFIG = testConfig();

const CONTRACT_STATE = await initialSingletonStateHex();

const SINGLETON = "d7b3c45da613be25050bbdf3fde4cef8f66154d3a52ca8c1edd878bd6391f169";
const REQUEST_ID = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";

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
    contractState: CONTRACT_STATE,
    ledgerParameters: toHex(LedgerParameters.initialParameters().serialize()),
    coinPublicKey: "44".repeat(32),
    ttlSeconds: 1_800_000_000,
    ...overrides,
  });

const answer = async (line: string) => JSON.parse(await handleLine(CONFIG, line));

afterEach(() => closePublisher());

describe("handleLine", () => {
  it("answers a valid request with a tagged intent and the same id", async () => {
    const reply = await answer(request());

    expect(reply.id).toBe(7);
    expect(reply.ok).toBe(true);
    expect(reply.intent).toMatch(/^(?:[0-9a-f]{2})+$/);
    expect(Buffer.from(reply.intent, "hex").subarray(0, 20).toString("utf8")).toContain("midnight:intent[v9]");
  });

  it("answers a line, never a fragment: a reply carries no raw newline", async () => {
    expect(await handleLine(CONFIG, request())).not.toContain("\n");
    expect(await handleLine(CONFIG, "{not json")).not.toContain("\n");
  });

  it("delivers the wire's own signature to the circuit, in the wire's own order", async () => {
    // Field names cross as strings; only the decoded call pins that JSON `bigR.x` is
    // the value the circuit received as x.
    const reply = await answer(request());

    const bytes = Buffer.from(reply.intent, "hex");
    expect(calledEntryPoint(bytes)).toBe("respond");
    expect(pushedCallArgs(bytes)).toBe(`pushs <[${X}, ${Y}, ${S}, -]: b32b32b32b1>`);
  });

  it("builds respondBidirectional from the same signature-only request shape", async () => {
    const reply = await answer(request({ circuit: "respondBidirectional" }));

    expect(reply.ok).toBe(true);
    const bytes = Buffer.from(reply.intent, "hex");
    expect(calledEntryPoint(bytes)).toBe("respondBidirectional");
    expect(pushedCallArgs(bytes)).toBe(`pushs <[${X}, ${Y}, ${S}, -]: b32b32b32b1>`);
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
      // `Buffer.from` truncates an odd digit silently, so the schema is the only guard.
      [{ ledgerParameters: "abc" }, "ledgerParameters"],
    ];

    for (const [override, field] of cases) {
      const reply = await answer(request(override));
      expect(reply, field).toMatchObject({ id: 7, ok: false, code: "bad_request" });
      expect(reply.message).toContain(field);
    }
  });

  it("reports the FIRST invalid field in declaration order, which is what makes that order a contract", async () => {
    const both = await answer(request({ contractAddress: "00", requestId: "00" }));
    expect(both.message).toContain("contractAddress");
    expect(both.message).not.toContain("requestId");

    const withBadId = await answer(request({ id: 1.5, contractAddress: "00" }));
    expect(withBadId.message).toContain("`id`");
    expect(withBadId.message).not.toContain("contractAddress");
  });

  it("rejects an id JSON cannot round-trip, rather than echoing a different one", async () => {
    // 2^53+1 parses to 2^53, so echoing it would answer a post the caller never sent.
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
    const reply = await answer(request({ contractState: toHex(new ContractState().serialize()) }));

    expect(reply).toMatchObject({ id: 7, ok: false, code: "contract_mismatch" });
    expect(reply.message).toContain("respond");
  });

  it("answers `internal` when the request is well formed but the bytes are not", async () => {
    // Valid hex of the wrong thing: the failure comes out of the ledger's own deserializer.
    const reply = await answer(request({ contractState: "00".repeat(64) }));

    expect(reply).toMatchObject({ id: 7, ok: false, code: "internal" });
    expect(reply.message.length).toBeGreaterThan(0);
  });
});

describe("handleLine: the operation discriminator", () => {
  it("treats an absent op and an explicit build as the same request", async () => {
    const implicit = await answer(request());
    const explicit = await answer(request({ op: "build" }));

    expect(implicit).toMatchObject({ id: 7, ok: true });
    expect(explicit).toMatchObject({ id: 7, ok: true });
  });

  it("names `op` when it is neither, rather than reporting a missing circuit", async () => {
    const reply = await answer(JSON.stringify({ id: 7, op: "publish", intent: "00" }));

    expect(reply).toMatchObject({ id: 7, ok: false, code: "bad_request" });
    expect(reply.message).toContain("`op`");
  });

  it("round-trips a submit's id alongside the transaction id and the block it landed in", async () => {
    primeStub();
    const built = await answer(request());

    const reply = await answer(JSON.stringify({ id: 21, op: "submit", intent: built.intent }));

    expect(reply).toEqual({ id: 21, ok: true, txId: STUB_TX_ID, blockHash: STUB_BLOCK_HASH });
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
    const built = await answer(request());

    const reply = await answer(JSON.stringify({ id: 24, op: "submit", intent: built.intent }));

    expect(reply).toMatchObject({ id: 24, ok: false, code: "wallet_unsynced" });
    expect(reply.message).toContain("MIDNIGHT_PUB_NODE_URL");
  });
});

it("committed initial-singleton-state.mn matches the in-process synthesis", async () => {
  const committed = readFileSync(new URL("./fixtures/initial-singleton-state.mn", import.meta.url));
  expect(Buffer.from(committed).toString("hex")).toBe(await initialSingletonStateHex());
});
