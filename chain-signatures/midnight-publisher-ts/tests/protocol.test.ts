// The wire end to end: `handleLine` is the whole process minus stdin, so what passes
// here is what the Rust client will see.

import { readFileSync } from "node:fs";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ContractState } from "@midnight-ntwrk/compact-runtime";

const submitMocks = vi.hoisted(() => ({ warmupPublisher: vi.fn() }));

vi.mock("../src/submit.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/submit.js")>()),
  warmupPublisher: submitMocks.warmupPublisher,
}));

import { handleLine } from "../src/protocol.js";
import { closePublisher } from "../src/submit.js";
import {
  initialSingletonStateHex,
  primeStub,
  respondInput,
  STUB_TX_ID,
  testConfig,
  toHex,
} from "./support.js";

const CONFIG = testConfig();

const BUILD = await respondInput();

const request = (overrides: Record<string, unknown> = {}): string =>
  JSON.stringify({
    id: 7,
    op: "build",
    ...BUILD,
    ...overrides,
  });

const answer = async (line: string) => JSON.parse(await handleLine(CONFIG, line));

beforeEach(() => submitMocks.warmupPublisher.mockClear());
afterEach(() => closePublisher());

describe("handleLine", () => {
  it("answers a valid request with a tagged intent and the same id", async () => {
    const reply = await answer(request());

    expect(reply.id).toBe(7);
    expect(reply.ok).toBe(true);
    expect(reply.intent).toMatch(/^(?:[0-9a-f]{2})+$/);
    expect(Buffer.from(reply.intent, "hex").subarray(0, 20).toString("utf8")).toContain(
      "midnight:intent[v9]",
    );
  });

  it("answers malformed JSON values with bad_request", async () => {
    for (const line of ["{not json", "[]"]) {
      expect(await answer(line)).toMatchObject({ ok: false, code: "bad_request" });
    }
  });

  it("echoes only a usable id from a rejected request", async () => {
    expect(await answer(JSON.stringify({ id: 9, circuit: "nope" }))).toMatchObject({
      id: 9,
      ok: false,
    });
    expect(await answer("{not json")).toMatchObject({ id: null });
    expect(await answer(JSON.stringify({ id: "7", circuit: "respond" }))).toMatchObject({
      id: null,
    });
  });

  it("names the offending field in a rejection", async () => {
    const cases: readonly [Record<string, unknown>, string][] = [
      [{ contractAddress: "00" }, "contractAddress"],
      [
        { signature: { bigR: { x: "11".repeat(32) }, s: "33".repeat(32), recoveryId: 0 } },
        "signature.bigR.y",
      ],
      [{ ttlSeconds: 0 }, "ttlSeconds"],
      [{ contractAddress: "AB".repeat(32) }, "contractAddress"],
      [{ contractState: "ZZ" }, "contractState"],
      // `Buffer.from` truncates an odd digit silently, so the schema is the only guard.
      [{ ledgerParameters: "abc" }, "ledgerParameters"],
      [{ signature: { ...BUILD.signature, recoveryId: 2 } }, "signature.recoveryId"],
    ];

    for (const [override, field] of cases) {
      const reply = await answer(request(override));
      expect(reply, field).toMatchObject({ id: 7, ok: false, code: "bad_request" });
      expect(reply.message).toContain(field);
    }
  });

  it("rejects an id JSON cannot round-trip, rather than echoing a different one", async () => {
    // 2^53+1 parses to 2^53, so echoing it would answer a post the caller never sent.
    const tooBig = await answer(request().replace('"id":7', '"id":9007199254740993'));
    expect(tooBig).toMatchObject({ id: null, ok: false, code: "bad_request" });
    expect(tooBig.message).toContain("`id`");

    expect(await answer(request({ id: -1 }))).toMatchObject({
      id: null,
      ok: false,
      code: "bad_request",
    });
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
  it("reports timing and starts publisher warmup at readiness", async () => {
    await expect(
      answer(JSON.stringify({ id: 6, op: "ready", protocolVersion: 1 })),
    ).resolves.toEqual({
      id: 6,
      ok: true,
      ready: true,
      protocolVersion: 1,
      submitTimeoutMs: 6 * 60 * 1_000,
      recipeTtlMs: 5 * 60 * 1_000,
    });
    expect(submitMocks.warmupPublisher).toHaveBeenCalledExactlyOnceWith(CONFIG);
  });

  it("requires the exact protocol version on ready", async () => {
    for (const protocolVersion of [undefined, 0, 2, "1", null]) {
      const reply = await answer(JSON.stringify({ id: 6, op: "ready", protocolVersion }));

      expect(reply, String(protocolVersion)).toMatchObject({
        id: 6,
        ok: false,
        code: "bad_request",
      });
      expect(reply.message).toContain("protocolVersion");
    }
    expect(submitMocks.warmupPublisher).not.toHaveBeenCalled();
  });

  it("requires an explicit build operation", async () => {
    const missing = await answer(JSON.stringify({ id: 7, ...BUILD }));
    const explicit = await answer(request());

    expect(missing).toMatchObject({ id: 7, ok: false, code: "bad_request" });
    expect(missing.message).toContain("`op`");
    expect(explicit).toMatchObject({ id: 7, ok: true });
    expect(submitMocks.warmupPublisher).not.toHaveBeenCalled();
  });

  it("names `op` when it is neither, rather than reporting a missing circuit", async () => {
    for (const op of ["publish", "warmup"]) {
      const reply = await answer(JSON.stringify({ id: 7, op, intent: "00" }));
      expect(reply, op).toMatchObject({ id: 7, ok: false, code: "bad_request" });
      expect(reply.message).toContain("`op`");
    }
    expect(submitMocks.warmupPublisher).not.toHaveBeenCalled();
  });

  it("round-trips a submit's id alongside the transaction id", async () => {
    primeStub();
    const built = await answer(request());

    const reply = await answer(JSON.stringify({ id: 21, op: "submit", intent: built.intent }));

    expect(reply).toEqual({ id: 21, ok: true, txId: STUB_TX_ID });
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
});

it("committed initial-singleton-state.mn matches the in-process synthesis", async () => {
  const committed = readFileSync(new URL("./fixtures/initial-singleton-state.mn", import.meta.url));
  expect(Buffer.from(committed).toString("hex")).toBe(await initialSingletonStateHex());
});
