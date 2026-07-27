// `POST /decode/contract-state` tests. Offline by design: the seam is a pure
// codec. The `.mn` fixtures are contract-state blobs read off the live local
// chain over RPC, so the input is real.

import { StateMap, StateValue, type AlignedValue } from "@midnightntwrk/ledger-v9";
import { describe, expect, it } from "vitest";

import { toHex } from "@midnight-ntwrk/midnight-js-utils";
import type { Reply } from "../src/errors.js";
import { decodeContractState, walk } from "../src/state.js";
import { fixtureBytes, get, goldenText, post } from "./support.js";

const SINGLETON = "aa5d96c2de9af9dfc9fe046c30954a07c32ae1e1c976bf6088f8757d06ff3f47";
const REQUEST_ID = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";

// Spelled out rather than imported, so these pin the wire shape.
function failure(code: string, message: string): string {
  return JSON.stringify({ code, message });
}

function parseFailure(reply: Reply): { code: string; message: string } {
  return JSON.parse(reply.body) as { code: string; message: string };
}

// The goldens are the decoder's own frozen output, so they detect a wire change
// rather than proving correctness. What anchors that is below: a synthetic map
// walked out of order, and the v8 -> v9 flip driven through the ledger's own
// deserializer.
describe("offline: the decoded tree is byte-identical to the captured golden's", () => {
  const TREE_GOLDENS: ReadonlyArray<readonly [string, string]> = [
    ["singleton-post-state-1366.mn", "golden-state-singleton-1366.json"],
    ["singleton-pre-state-1365.mn", "golden-state-singleton-1365.json"],
  ];

  it.each(TREE_GOLDENS)("%s decodes to %s's tree", (fixture, golden) => {
    // Raw text, never parsed: `JSON.parse` would launder key order.
    expect(JSON.stringify(decodeContractState(fixtureBytes(fixture)))).toBe(goldenText(golden));
  });

  it.each(TREE_GOLDENS)("%s served over HTTP is %s's tree, byte for byte", async (fixture, golden) => {
    const body = JSON.stringify({ state: toHex(fixtureBytes(fixture)) });
    expect(await post("/decode/contract-state", body)).toEqual({ status: 200, body: goldenText(golden) });
  });
});

describe("offline: the schema the consumer parses", () => {
  it("tags every node on `kind`, serialized first", () => {
    const tree = decodeContractState(fixtureBytes("caller-state-1366.mn"));
    expect(tree.kind).toBe("array");
    // `kind` must serialize FIRST: the consumer's union parser depends on it.
    expect(JSON.stringify(tree).startsWith('{"kind":"array","children":[')).toBe(true);
  });

  it("extracts trailing-zero-trimmed atoms in declaration order", () => {
    const tree = decodeContractState(fixtureBytes("caller-state-1366.mn"));
    if (tree.kind !== "array") throw new Error(`the caller ledger is an ordinal array, got ${tree.kind}`);

    // Ordinal 3 is the hub address, ordinal 2 its MPC attestation Secp256k1Point:
    // 24- and 8-byte atoms in declaration order, trailing-zero-trimmed.
    expect(tree.children[3]).toEqual({ kind: "cell", atoms: [SINGLETON] });
    expect(tree.children[2]).toEqual({
      kind: "cell",
      atoms: [
        "231b0992a4116fa52d0dcc9a19752b3854aef6ab58d9528c",
        "0b1516d5a2f1909a",
        "88f8208ba07291ba4bc108f5ff853b4e7202fcfa8e54d1be",
        "d71494b2d5d4a256",
        "",
      ],
    });
    // Ordinal 0 nests the live request, whose null nodes and empty atom pin the
    // rest of the node vocabulary.
    if (tree.children[0]?.kind !== "array") throw new Error("ordinal 0 is the request block");
    expect(tree.children[0].children[0]).toEqual({ kind: "cell", atoms: [REQUEST_ID] });
    expect(tree.children[0].children[1]).toEqual({
      kind: "array",
      children: [{ kind: "null" }, { kind: "null" }, { kind: "cell", atoms: [""] }],
    });
    const requests = tree.children[4];
    if (requests?.kind !== "map") throw new Error("ordinal 4 is the request map");
    expect(requests.entries.map((entry) => entry.key)).toEqual([[REQUEST_ID]]);
  });

  it("sorts map entries by key hex", () => {
    // The live signet maps hold one entry, so this uses a synthetic map inserted
    // out of order and walked through the real decoder.
    const key = (byte: number): AlignedValue => ({
      value: [Uint8Array.from([byte])],
      alignment: [{ tag: "atom", value: { tag: "field" } }],
    });
    const map = new StateMap()
      .insert(key(0x02), StateValue.newNull())
      .insert(key(0x01), StateValue.newNull())
      .insert(key(0x03), StateValue.newNull());

    const node = walk(StateValue.newMap(map));
    if (node.kind !== "map") throw new Error(`expected a map node, got ${node.kind}`);
    expect(node.entries.map((entry) => entry.key)).toEqual([["01"], ["02"], ["03"]]);
  });
});

describe("POST /decode/contract-state: the envelope", () => {
  it("rejects a JSON array as bad_request", async () => {
    expect(await post("/decode/contract-state", "[]")).toEqual({
      status: 400,
      body: failure("bad_request", "invalid JSON: expected a JSON object"),
    });
  });

  it("rejects a body that is not JSON as bad_request", async () => {
    const reply = await post("/decode/contract-state", "{");
    expect(reply.status).toBe(400);
    expect(parseFailure(reply)).toMatchObject({ code: "bad_request" });
    expect(parseFailure(reply).message).toMatch(/^invalid JSON:/);
  });

  // `fromHex` truncates silently at the first non-hex character, so without this
  // pre-check a caller-side hex bug returns `decode_failed` for an envelope
  // mistake. The 400/422 split is the caller-action split.
  const REJECTED_BYTES: ReadonlyArray<readonly [string, string, string]> = [
    ["a missing `state`", "{}", "`state` must be a hex string"],
    ["a non-string `state`", '{"state":123}', "`state` must be a hex string"],
    ["an array `state`", '{"state":["00"]}', "`state` must be a hex string"],
    ["odd-length hex", '{"state":"abc"}', "`state` must be non-empty bare lowercase hex, no `0x` prefix"],
    ["hex that is not hex", '{"state":"zz"}', "`state` must be non-empty bare lowercase hex, no `0x` prefix"],
    ["an empty `state`", '{"state":""}', "`state` must be non-empty bare lowercase hex, no `0x` prefix"],
    ["a bare `0x`", '{"state":"0x"}', "`state` must be non-empty bare lowercase hex, no `0x` prefix"],
  ];

  it.each(REJECTED_BYTES)("rejects %s as bad_request", async (_what, body, expected) => {
    expect(await post("/decode/contract-state", body)).toEqual({
      status: 400,
      body: failure("bad_request", expected),
    });
  });

  // One spelling only. A caller that guesses the other is told so, rather than
  // being quietly accommodated into two renderings of the same blob.
  it.each([
    ["0x-prefixed", (hex: string) => `0x${hex}`],
    ["upper-case", (hex: string) => hex.toUpperCase()],
  ])("rejects %s hex", async (_what, spell) => {
    const hex = toHex(fixtureBytes("singleton-post-state-1366.mn"));
    expect(await post("/decode/contract-state", JSON.stringify({ state: hex }))).toMatchObject({ status: 200 });
    expect(await post("/decode/contract-state", JSON.stringify({ state: spell(hex) }))).toEqual({
      status: 400,
      body: failure("bad_request", "`state` must be non-empty bare lowercase hex, no `0x` prefix"),
    });
  });

  it("answers decode_failed, not bad_request, when the envelope is fine and the ledger refuses the bytes", async () => {
    // `bad_request` means "fix your request", `decode_failed` means "these bytes
    // are not a contract state this build can read".
    const reply = await post("/decode/contract-state", '{"state":"deadbeef"}');
    expect(reply.status).toBe(422);
    expect(parseFailure(reply).code).toBe("decode_failed");
    expect(parseFailure(reply).message.length).toBeGreaterThan(0);
  });

  it("separates a chain that moved ahead from a caller's bad blob", async () => {
    // The library classifies BOTH as `version-mismatch`, so only a received
    // version distinguishes them, and getting it wrong sends the operator to the
    // wrong place: "fix your blob" versus "this build is too old for this chain".
    const real = fixtureBytes("singleton-post-state-1366.mn");
    const skewed = Uint8Array.from(real);
    // `midnight:contract-state[v8]` -> `[v9]`, one byte, leaving a real blob.
    const tag = Buffer.from(real).indexOf("midnight:contract-state[v8]");
    expect(tag).toBeGreaterThanOrEqual(0);
    skewed[tag + "midnight:contract-state[v".length] = "9".charCodeAt(0);

    const ahead = await post("/decode/contract-state", JSON.stringify({ state: toHex(skewed) }));
    expect(parseFailure(ahead).code).toBe("ledger_mismatch");

    const junk = await post("/decode/contract-state", '{"state":"deadbeef"}');
    expect(parseFailure(junk).code).toBe("decode_failed");
  });

  it("is not reachable by GET, and says so with a code", async () => {
    // The decode seams are POST-only by design, and the old GET spelling must not
    // half-work. Every failure carries a code, a routing mistake included.
    const reply = await get("/decode/contract-state");
    expect(reply.status).toBe(404);
    expect(parseFailure(reply).code).toBe("not_found");
  });
});

describe("GET /health", () => {
  it("declares which ledger this build speaks, and which network it posts to", async () => {
    // The publisher's ENTIRE compatibility surface, asserted by the caller at
    // startup so skew fails here rather than later on good bytes.
    const reply = await get("/health");
    expect(reply.status).toBe(200);
    expect(JSON.parse(reply.body)).toEqual({
      status: "ok",
      networkId: "undeployed",
      ledger: {
        contractState: "midnight:contract-state[v8]",
        zswapChainState: "midnight:zswap-ledger-state[v5]",
        ledgerParameters: "midnight:ledger-parameters[v8]",
        transaction: "midnight:transaction[v12]",
      },
    });
  });

  it("needs no node", async () => {
    // Liveness only: a caller that treats an unreachable dependency as "publisher
    // down" restarts the wrong process.
    await expect(get("/health")).resolves.toMatchObject({ status: 200 });
  });
});
