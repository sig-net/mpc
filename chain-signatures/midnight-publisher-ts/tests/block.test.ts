/**
 * `POST /decode/transactions` tests.
 *
 * All offline, and that is the point: the seam is a pure codec, so there is
 * nothing left that a running node could tell us.
 * `tests/fixtures/rust-block-1366.json` is the VERBATIM `GET /block` body of the
 * Rust `midnight-publisher` binary for block 1366, and `notify-tx.mn` holds that
 * block's one transaction. Block 1366 carried exactly one transaction slot, so
 * decoding that single blob must still reproduce the golden byte for byte:
 * correctness stays anchored to the reference implementation rather than to
 * hand-written expectations, even though the caller now hands the bytes over
 * instead of this service walking the block for them.
 *
 * The live and acceptance tiers this file used to carry pulled the transaction
 * out of a real block's extrinsics and byte-diffed `GET /block` against the Rust
 * binary. Neither endpoint exists on either side now; the coverage they gave —
 * same bytes, same decoder, same golden — is kept by driving the fixture through
 * the real HTTP server below. Unwrapping the blob out of a block is the caller's
 * job, and its traps are recorded in `src/block.ts`.
 */

import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";

import { ContractCall } from "@midnightntwrk/ledger-v9";
import { describe, expect, it } from "vitest";

import {
  callsFromTx,
  compareClaimedCalls,
  decodeTransaction,
  decodeTransactions,
  type ClaimedCall,
} from "../src/block.js";
import { toHex } from "@midnight-ntwrk/midnight-js-utils";
import type { Config } from "../src/config.js";
import { fromHex, type NodeClient } from "../src/node.js";
import type { Reply } from "../src/errors.js";
import { buildServer } from "../src/server.js";
import { decodeContractState, type StateNode } from "../src/state.js";

/** The deployed singleton and caller of the captured SGN2 flow, and the request the caller submitted. */
const SINGLETON = "aa5d96c2de9af9dfc9fe046c30954a07c32ae1e1c976bf6088f8757d06ff3f47";
const CALLER = "dcd470fbc066befe0b6cddcf273dc9a838832ccbb8327f2625ec7028b0a6f0d2";
const REQUEST_ID = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";

const FIXTURES = fileURLToPath(new URL("./fixtures/", import.meta.url));

/**
 * A fixture's transaction bytes. The captured fixtures carry only the `tx`
 * member of the toolkit's `SerializedTx`, tagged with its chain.
 */
function fixtureTxBytes(name: string): Uint8Array {
  const parsed: unknown = JSON.parse(readFileSync(`${FIXTURES}${name}`, "utf8"));
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    !("tx" in parsed) ||
    typeof parsed.tx !== "object" ||
    parsed.tx === null ||
    !("Midnight" in parsed.tx) ||
    typeof parsed.tx.Midnight !== "string"
  ) {
    throw new Error(`${name} does not hold a Midnight RawTransaction`);
  }
  return fromHex(parsed.tx.Midnight);
}

function fixtureBytes(name: string): Uint8Array {
  return Uint8Array.from(readFileSync(`${FIXTURES}${name}`));
}

function goldenText(name: string): string {
  return readFileSync(`${FIXTURES}${name}`, "utf8");
}

/** A config with only the fields the server itself could consult. */
const TEST_CONFIG: Config = {
  port: 0,
  bindHost: "127.0.0.1",
  nodeUrl: "ws://127.0.0.1:1",
  proofServerUrl: "http://127.0.0.1:1",
  indexerUrl: "http://127.0.0.1:1",
  indexerWsUrl: "ws://127.0.0.1:1",
  managedDir: FIXTURES,
  fundingSeed: "deadbeef".repeat(8),
  networkId: "undeployed",
};

/**
 * A node client that must never be reached. The decode seams are pure codecs, so
 * ANY property access here is a bug: this is what proves the read path opens no
 * connection, rather than merely not needing one.
 */
const FORBIDDEN_CLIENT = new Proxy({} as NodeClient, {
  get(_target, property) {
    throw new Error(`a decode seam touched the node client (${String(property)})`);
  },
});

/**
 * Round-trip a body through the REAL HTTP server, on an ephemeral port.
 *
 * @param path - Request path.
 * @param body - Raw request body.
 * @returns The status and body the server answered with.
 */
async function post(path: string, body: string): Promise<Reply> {
  const server = buildServer(TEST_CONFIG, FORBIDDEN_CLIENT);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  try {
    const { port } = server.address() as AddressInfo;
    const response = await fetch(`http://127.0.0.1:${port}${path}`, { method: "POST", body });
    return { status: response.status, body: await response.text() };
  } finally {
    server.closeAllConnections();
    server.close();
  }
}

/** A `POST /decode/transactions` body carrying the named fixtures' transactions, in order. */
function txBody(...names: readonly string[]): string {
  return JSON.stringify({ bytes: names.map((name) => toHex(fixtureTxBytes(name))) });
}

describe("offline: the decoded transactions are byte-identical to the Rust seam's", () => {
  it("reproduces the Rust binary's block-1366 body exactly", () => {
    // Block 1366 held exactly one transaction slot, so decoding the captured
    // transaction alone must reproduce the whole response: field order
    // (transactions/skipped, index/calls, address/communication_commitment/
    // claimed, position/address/entry_point/commitment), the stripped Fr tag,
    // and the claimed-call ordering all have to match at once.
    expect(JSON.stringify(decodeTransactions([fixtureTxBytes("notify-tx.mn")]))).toBe(
      goldenText("rust-block-1366.json"),
    );
  });

  it("reproduces it over HTTP too", async () => {
    expect(await post("/decode/transactions", txBody("notify-tx.mn"))).toEqual({
      status: 200,
      body: goldenText("rust-block-1366.json"),
    });
  });
});

describe("offline: the ledger-v9 Fr tag", () => {
  it("is stripped, and the raw value really does carry it", () => {
    const tx = decodeTransaction(fixtureTxBytes("notify-tx.mn"));
    const calls = callsFromTx(tx);

    // The pin: the ledger hands back a TAGGED Fr, 33 bytes with a leading 0x73.
    // If this ever stops holding, the constant in src/block.ts is wrong and every
    // commitment below silently changes width.
    const tagged: string[] = [];
    for (const intent of tx.intents?.values() ?? []) {
      for (const action of intent.actions) {
        if (action instanceof ContractCall) tagged.push(action.communicationCommitment);
      }
    }
    expect(tagged.length, "the fixture must carry contract calls to pin the tag against").toBe(2);
    for (const value of tagged) {
      expect(value).toHaveLength(66);
      expect(value.slice(0, 2)).toBe("73");
    }

    // ...and every commitment this seam emits is the bare 32-byte value Rust's
    // `Fr::as_le_bytes()` produces.
    for (const call of calls) {
      expect(call.communication_commitment).toMatch(/^[0-9a-f]{64}$/);
      for (const claim of call.claimed) expect(claim.commitment).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});

describe("offline: claimed calls are ordered", () => {
  it("sorts by position, then by commitment hex", () => {
    // Every captured transaction claims exactly one call from exactly one
    // transcript, so no fixture can exercise this. Pinned directly instead.
    const entry = (position: number, commitment: string): ClaimedCall => ({
      position,
      address: SINGLETON,
      entry_point: "00".repeat(32),
      commitment,
    });
    const ordered = [
      entry(2, "aa".repeat(32)),
      entry(0, "ff".repeat(32)),
      entry(1, "bb".repeat(32)),
      entry(0, "00".repeat(32)),
    ].sort(compareClaimedCalls);

    expect(ordered.map((claim) => [claim.position, claim.commitment.slice(0, 2)])).toEqual([
      [0, "00"],
      [0, "ff"],
      [1, "bb"],
      [2, "aa"],
    ]);
  });
});

describe("offline: cross-call provenance", () => {
  it("links the caller to the singleton inside ONE transaction", () => {
    // The Step-3 evidence this seam exists to provide.
    const calls = callsFromTx(decodeTransaction(fixtureTxBytes("notify-tx.mn")));
    const caller = calls.find((call) => call.address === CALLER);
    const singleton = calls.find((call) => call.address === SINGLETON);
    expect(caller, "the caller's contract call").toBeDefined();
    expect(singleton, "the singleton's contract call").toBeDefined();

    const claim = caller?.claimed.find((entry) => entry.address === SINGLETON);
    expect(claim, "the caller must claim a call on the singleton").toBeDefined();
    expect(claim?.commitment).toBe(singleton?.communication_commitment);
  });

  it("decodes the pre-SGN2 reference transaction into a well-formed response", () => {
    // It may carry zero contract calls; that is asserted as well-formed, not required.
    const response = decodeTransactions([fixtureTxBytes("serialized_tx.mn")]);
    expect(response.skipped).toEqual([]);
    expect(response.transactions).toHaveLength(1);
    expect(response.transactions[0]?.calls).toHaveLength(
      callsFromTx(decodeTransaction(fixtureTxBytes("serialized_tx.mn"))).length,
    );
    expect(JSON.stringify(response).startsWith('{"transactions":')).toBe(true);
  });
});

describe("offline: one bad transaction costs that transaction only", () => {
  it("keeps the real calls beside a poisoned one and reports the drop", () => {
    const response = decodeTransactions([
      Uint8Array.from([0xde, 0xad, 0xbe, 0xef]),
      fixtureTxBytes("notify-tx.mn"),
    ]);

    expect(response.transactions).toHaveLength(1);
    expect(response.transactions[0]?.calls.some((call) => call.address === SINGLETON)).toBe(true);
    expect(response.skipped).toHaveLength(1);
    expect(response.skipped[0]?.startsWith("tx[0]:")).toBe(true);
  });

  it("survives per item over HTTP, and never renumbers what follows a drop", async () => {
    // `index` is the position in the REQUEST's `bytes` array, so the caller can
    // map a result back to the blob it sent. Numbering by rank among the
    // successful ones instead would shift every transaction after a dropped one,
    // silently, and only for callers unlucky enough to hit an unknown shape.
    const bytes = ["deadbeef", toHex(fixtureTxBytes("notify-tx.mn"))];
    const reply = await post("/decode/transactions", JSON.stringify({ bytes }));
    expect(reply.status).toBe(200);

    const decoded = JSON.parse(reply.body) as { transactions: { index: number }[]; skipped: string[] };
    expect(decoded.transactions.map((tx) => tx.index)).toEqual([1]);
    expect(decoded.skipped).toHaveLength(1);
    expect(decoded.skipped[0]?.startsWith("tx[0]:")).toBe(true);
  });

  it("accepts an empty batch", () => {
    // A block with no midnight transactions is a normal answer, not an error.
    expect(JSON.stringify(decodeTransactions([]))).toBe('{"transactions":[],"skipped":[]}');
  });
});

/**
 * Every `(map key hex, cell atoms)` pair reachable in a walked state tree.
 *
 * Mirrors the Rust `block.rs` test helper of the same name: it lives with these
 * tests because it exists to demonstrate the seam's central design claim, that a
 * state diff already answers "what did this block write".
 */
function mapEntries(node: StateNode): Array<[string, readonly string[]]> {
  const out: Array<[string, readonly string[]]> = [];
  if (node.kind === "map") {
    for (const entry of node.entries) {
      if (entry.value.kind === "cell") out.push([entry.key, entry.value.atoms]);
      out.push(...mapEntries(entry.value));
    }
  } else if (node.kind === "array") {
    for (const child of node.children) out.push(...mapEntries(child));
  }
  return out;
}

/** Stable identity for a `(key, atoms)` pair, for set membership. */
function entryKey([key, atoms]: readonly [string, readonly string[]]): string {
  return `${key}|${atoms.join(",")}`;
}

describe("offline: a state diff yields the notify", () => {
  it("reproduces state_diff_yields_the_notify", () => {
    // THE load-bearing test for this seam's design: what a block wrote is the
    // difference between the contract's state at that block and at its parent.
    // No transcript is decoded here at all.
    //
    // The fixtures are the singleton's real state read from the node either side
    // of the notify block 1366. The stored map key renders as one hex string, so
    // `SignetMapKey{count: 0, requestId}` appears as the request id alone (the
    // zero count trims away).
    const before = decodeContractState(fixtureBytes("singleton-pre-state-1365.mn"));
    const after = decodeContractState(fixtureBytes("singleton-post-state-1366.mn"));

    const seen = new Set(mapEntries(before).map(entryKey));
    const written = mapEntries(after).filter((entry) => !seen.has(entryKey(entry)));

    // Exactly two writes: the per-request notification counter, and the
    // notification itself.
    expect(written).toHaveLength(2);
    expect(written).toContainEqual([REQUEST_ID, ["01"]]);
    expect(written).toContainEqual([REQUEST_ID, ["01", `${CALLER}04`]]);
  });
});

describe("POST /decode/transactions: the envelope", () => {
  // The envelope fails the whole request as `bad_request`; only bytes the LEDGER
  // refuses survive per item into `skipped`. Without the pre-check, a caller-side
  // hex typo would be `fromHex`-truncated silently and burn a whole batch as
  // per-item skips, reading like ledger trouble instead of a request bug.
  const REJECTED: ReadonlyArray<readonly [string, string, string]> = [
    ["a missing `bytes`", "{}", "`bytes` must be an array of hex strings"],
    ["a bare string `bytes`", '{"bytes":"00"}', "`bytes` must be an array of hex strings"],
    ["a non-string element", '{"bytes":["00",7]}', "`bytes[1]` must be a hex string"],
    ["a non-hex element", '{"bytes":["00","zz"]}', "`bytes[1]` must be a whole number of bytes of hex, optionally `0x`-prefixed"],
  ];

  it.each(REJECTED)("rejects %s as bad_request", async (_what, body, expected) => {
    const reply = await post("/decode/transactions", body);
    expect(reply.status).toBe(400);
    expect(JSON.parse(reply.body)).toEqual({ code: "bad_request", message: expected });
  });

  it("accepts `0x`-prefixed hex", async () => {
    const bytes = [`0x${toHex(fixtureTxBytes("notify-tx.mn"))}`];
    expect(await post("/decode/transactions", JSON.stringify({ bytes }))).toEqual({
      status: 200,
      body: goldenText("rust-block-1366.json"),
    });
  });
});
