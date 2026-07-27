// `POST /decode/transactions` tests. Offline by design: the seam is a pure
// codec. `notify-tx.mn` holds block 1366's one transaction, read off the live
// local chain, so the input is real. Unwrapping the blob out of a block is the
// caller's job, and its traps are recorded in `src/block.ts`.

import { readFileSync } from "node:fs";

import { ContractCall } from "@midnightntwrk/ledger-v9";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import {
  callsFromTx,
  compareClaimedCalls,
  decodeTransaction,
  decodeTransactions,
  type ClaimedCall,
} from "../src/block.js";
import { toHex } from "@midnight-ntwrk/midnight-js-utils";
import { fromHex } from "../src/node.js";
import { decodeContractState, type StateNode } from "../src/state.js";
import { FIXTURES, fixtureBytes, goldenText, post } from "./support.js";

const SINGLETON = "aa5d96c2de9af9dfc9fe046c30954a07c32ae1e1c976bf6088f8757d06ff3f47";
const CALLER = "dcd470fbc066befe0b6cddcf273dc9a838832ccbb8327f2625ec7028b0a6f0d2";
const REQUEST_ID = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";

// Parsed, not cast: a recaptured fixture with the wrong shape must name itself here.
function fixtureTxBytes(name: string): Uint8Array {
  const { tx } = z.object({ tx: z.object({ Midnight: z.string() }) }).parse(JSON.parse(readFileSync(`${FIXTURES}${name}`, "utf8")));
  return fromHex(tx.Midnight);
}

describe("offline: the decoded transactions are byte-identical to the captured golden's", () => {
  it("reproduces the golden's block-1366 body exactly", () => {
    // Block 1366 held one transaction slot, so decoding that blob alone must
    // reproduce the whole response: field order, the stripped Fr tag, and the
    // claimed-call ordering all have to match at once.
    expect(JSON.stringify(decodeTransactions([fixtureTxBytes("notify-tx.mn")]))).toBe(
      goldenText("golden-block-1366.json"),
    );
  });
});

describe("offline: the ledger-v9 Fr tag", () => {
  it("is stripped, and the raw value really does carry it", () => {
    const tx = decodeTransaction(fixtureTxBytes("notify-tx.mn"));
    const calls = callsFromTx(tx);

    // If this stops holding, the constant in src/block.ts is wrong and every
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

    for (const call of calls) {
      expect(call.communication_commitment).toMatch(/^[0-9a-f]{64}$/);
      for (const claim of call.claimed) expect(claim.commitment).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});

describe("offline: claimed calls are ordered", () => {
  it("sorts by position, then by commitment hex", () => {
    // No fixture can exercise this: every capture claims one call from one transcript.
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
    const calls = callsFromTx(decodeTransaction(fixtureTxBytes("notify-tx.mn")));
    const caller = calls.find((call) => call.address === CALLER);
    const singleton = calls.find((call) => call.address === SINGLETON);
    expect(caller, "the caller's contract call").toBeDefined();
    expect(singleton, "the singleton's contract call").toBeDefined();

    const claim = caller?.claimed.find((entry) => entry.address === SINGLETON);
    expect(claim, "the caller must claim a call on the singleton").toBeDefined();
    expect(claim?.commitment).toBe(singleton?.communication_commitment);
  });

  it("decodes a call-free transaction (the singleton deploy) into an empty calls list", () => {
    // A deploy has no transcript and no commitment, so the filter must drop it cleanly.
    expect(decodeTransactions([fixtureTxBytes("deploy-tx-1352.mn")])).toEqual({
      transactions: [{ index: 0, calls: [] }],
      skipped: [],
    });
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
    // Numbering by rank among the survivors would silently shift every
    // transaction after a dropped one.
    const bytes = ["deadbeef", toHex(fixtureTxBytes("notify-tx.mn"))];
    const reply = await post("/decode/transactions", JSON.stringify({ transactions: bytes }));
    expect(reply.status).toBe(200);

    const decoded = JSON.parse(reply.body) as { transactions: { index: number }[]; skipped: string[] };
    expect(decoded.transactions.map((tx) => tx.index)).toEqual([1]);
    expect(decoded.skipped).toHaveLength(1);
    expect(decoded.skipped[0]?.startsWith("tx[0]:")).toBe(true);
  });

  it("accepts an empty batch", () => {
    expect(JSON.stringify(decodeTransactions([]))).toBe('{"transactions":[],"skipped":[]}');
  });
});

// Every `(map key hex, cell atoms)` pair reachable in a walked state tree.
function mapEntries(node: StateNode): Array<[readonly string[], readonly string[]]> {
  const out: Array<[readonly string[], readonly string[]]> = [];
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

// Separators, not bare concatenation: `["", X]` and `[X]` are both in this fixture.
function entryKey([key, atoms]: readonly [readonly string[], readonly string[]]): string {
  return `${key.join(",")}|${atoms.join(",")}`;
}

describe("offline: a state diff yields the notify", () => {
  it("recovers exactly the two writes block 1366 made", () => {
    // THE load-bearing test for this seam's design: what a block wrote is the
    // difference between the contract's state either side of it, no transcript
    // decoded at all. `SignetMapKey{count: 0, requestId}` stores as
    // `["", requestId]`, the zero count trimming to an empty atom.
    const before = decodeContractState(fixtureBytes("singleton-pre-state-1365.mn"));
    const after = decodeContractState(fixtureBytes("singleton-post-state-1366.mn"));

    const seen = new Set(mapEntries(before).map(entryKey));
    const written = mapEntries(after).filter((entry) => !seen.has(entryKey(entry)));

    // The per-request notification counter, and the notification itself.
    expect(written).toHaveLength(2);
    expect(written).toContainEqual([[REQUEST_ID], ["01"]]);
    expect(written).toContainEqual([["", REQUEST_ID], ["01", `${CALLER}04`]]);
  });
});

describe("POST /decode/transactions: the envelope", () => {
  // The envelope fails the whole request; only bytes the LEDGER refuses survive
  // per item. Without the pre-check a hex typo burns a batch as per-item skips.
  const REJECTED: ReadonlyArray<readonly [string, string, string]> = [
    ["a missing `transactions`", "{}", "`transactions` must be an array of hex strings"],
    ["a bare string `transactions`", '{"transactions":"00"}', "`transactions` must be an array of hex strings"],
    ["a non-string element", '{"transactions":["00",7]}', "`transactions[1]` must be a hex string"],
    ["a non-hex element", '{"transactions":["00","zz"]}', "`transactions[1]` must be non-empty bare lowercase hex, no `0x` prefix"],
    ["an empty element", '{"transactions":["00",""]}', "`transactions[1]` must be non-empty bare lowercase hex, no `0x` prefix"],
  ];

  it.each(REJECTED)("rejects %s as bad_request", async (_what, body, expected) => {
    const reply = await post("/decode/transactions", body);
    expect(reply.status).toBe(400);
    expect(JSON.parse(reply.body)).toEqual({ code: "bad_request", message: expected });
  });

  it("rejects `0x`-prefixed hex", async () => {
    const hex = toHex(fixtureTxBytes("notify-tx.mn"));
    expect(await post("/decode/transactions", JSON.stringify({ transactions: [hex] }))).toEqual({
      status: 200,
      body: goldenText("golden-block-1366.json"),
    });
    const reply = await post("/decode/transactions", JSON.stringify({ transactions: [`0x${hex}`] }));
    expect(reply.status).toBe(400);
    expect(JSON.parse(reply.body)).toEqual({
      code: "bad_request",
      message: "`transactions[0]` must be non-empty bare lowercase hex, no `0x` prefix",
    });
  });
});
