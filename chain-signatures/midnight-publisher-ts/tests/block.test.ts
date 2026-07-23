/**
 * `/block` seam tests.
 *
 * Two tiers, deliberately separated:
 *
 * OFFLINE (always run) — golden tests against committed fixtures.
 * `tests/fixtures/rust-block-1366.json` is the VERBATIM `GET /block` body of the
 * Rust `midnight-publisher` binary for block 1366, and `notify-tx.mn` holds that
 * block's transaction. Decoding the fixture must reproduce the golden byte for
 * byte, so correctness is anchored to the reference implementation rather than
 * to hand-written expectations.
 *
 * LIVE (opt-in via `MIDNIGHT_PUB_TEST_NODE_URL`) — the half no fixture can
 * cover: pulling the transaction back out of a real block's extrinsics. That is
 * where the snake_case/camelCase trap lives, so it is asserted rather than
 * assumed.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { ContractCall } from "@midnightntwrk/ledger-v9";
import { ApiPromise, WsProvider } from "@polkadot/api";
import { describe, expect, it } from "vitest";

import type { Config } from "../src/config.js";
import {
  blockSlots,
  callsFromTx,
  compareClaimedCalls,
  decodeBlock,
  decodeTransaction,
  handleBlock,
  type ClaimedCall,
  type TransactionSlot,
} from "../src/block.js";
import { connect, fromHex, type BlockHashHex, type NodeClient } from "../src/node.js";
import { decodeContractState, type StateNode } from "../src/state.js";

/** The deployed singleton and caller of the captured SGN2 flow, and the request the caller submitted. */
const SINGLETON = "aa5d96c2de9af9dfc9fe046c30954a07c32ae1e1c976bf6088f8757d06ff3f47";
const CALLER = "dcd470fbc066befe0b6cddcf273dc9a838832ccbb8327f2625ec7028b0a6f0d2";
const REQUEST_ID = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";

const BLOCK_1366: BlockHashHex = "0x588b87380b6b17463ed87837fa5651a32b5a9d4f02deeb015661f1f04f0ad8fc";

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

/** One midnight slot per fixture transaction, in the order given. */
function midnightSlots(...names: readonly string[]): TransactionSlot[] {
  return names.map((name) => ({ kind: "midnight", bytes: fixtureTxBytes(name) }));
}

function fixtureBytes(name: string): Uint8Array {
  return Uint8Array.from(readFileSync(`${FIXTURES}${name}`));
}

function goldenText(name: string): string {
  return readFileSync(`${FIXTURES}${name}`, "utf8");
}

/** A config with only the fields the read seams could possibly consult. */
function testConfig(nodeUrl: string): Config {
  return {
    port: 0,
    bindHost: "127.0.0.1",
    nodeUrl,
    proofServerUrl: "http://127.0.0.1:6300",
    indexerUrl: "http://127.0.0.1:8088",
    indexerWsUrl: "ws://127.0.0.1:8088",
    managedDir: FIXTURES,
    fundingSeed: "0".repeat(64),
    networkId: "undeployed",
  };
}

/** A real but never-connected client: `autoConnect: false`, so no socket is ever opened. */
const OFFLINE_CLIENT: NodeClient = (() => {
  const provider = new WsProvider("ws://127.0.0.1:1", false);
  return { api: new ApiPromise({ provider, noInitWarn: true }), provider, disconnect: async () => {} };
})();

describe("offline: the decoded block is byte-identical to the Rust seam's", () => {
  it("reproduces the Rust binary's block-1366 body exactly", () => {
    // Block 1366 holds exactly one transaction slot, so decoding the captured
    // transaction alone must reproduce the whole response: field order
    // (transactions/skipped, index/calls, address/communication_commitment/
    // claimed, position/address/entry_point/commitment), the stripped Fr tag,
    // and the claimed-call ordering all have to match at once.
    expect(JSON.stringify(decodeBlock(midnightSlots("notify-tx.mn")))).toBe(
      goldenText("rust-block-1366.json"),
    );
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
    const response = decodeBlock(midnightSlots("serialized_tx.mn"));
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
    const response = decodeBlock([
      { kind: "midnight", bytes: Uint8Array.from([0xde, 0xad, 0xbe, 0xef]) },
      ...midnightSlots("notify-tx.mn"),
    ]);

    expect(response.transactions).toHaveLength(1);
    expect(response.transactions[0]?.calls.some((call) => call.address === SINGLETON)).toBe(true);
    expect(response.skipped).toHaveLength(1);
    expect(response.skipped[0]?.startsWith("tx[0]:")).toBe(true);
  });
});

describe("offline: system transactions occupy an index", () => {
  it("numbers a midnight transaction by its slot, not by its rank among midnight ones", () => {
    // The Rust fetcher appends a slot per `SystemTransactionApplied` event
    // alongside the `send_mn_transaction` ones, and `index` is the position in
    // that combined list. Counting only midnight transactions would renumber
    // everything after a system transaction, silently and only on chains that
    // have them (this one has none in 0..1400, which is exactly why it needs a
    // test rather than an observation).
    const response = decodeBlock([
      { kind: "system" },
      ...midnightSlots("notify-tx.mn"),
      { kind: "system" },
    ]);
    expect(response.transactions.map((tx) => tx.index)).toEqual([1]);
  });
});

/**
 * Every `(map key hex, cell atoms)` pair reachable in a walked state tree.
 *
 * Mirrors the Rust `block.rs` test helper of the same name: it lives with the
 * `/block` tests because it exists to demonstrate the seam's central design
 * claim, that a state diff already answers "what did this block write".
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

describe("offline: validation answers before any network call", () => {
  // Every message here is the Rust binary's verbatim 400 body.
  const REJECTED: ReadonlyArray<readonly [string, string]> = [
    ["/block", "missing `hash` query param"],
    ["/block?hash=abc", "hash must be `0x` followed by 64 lowercase hex"],
    [`/block?hash=${BLOCK_1366.slice(2)}`, "hash must be `0x` followed by 64 lowercase hex"],
    [`/block?hash=${BLOCK_1366}0`, "hash must be `0x` followed by 64 lowercase hex"],
    [`/block?hash=${BLOCK_1366.toUpperCase()}`, "hash must be `0x` followed by 64 lowercase hex"],
  ];

  it.each(REJECTED)("%s -> 400", async (path, body) => {
    const reply = await handleBlock(
      testConfig("ws://127.0.0.1:1"),
      OFFLINE_CLIENT,
      new URL(path, "http://localhost"),
    );
    expect(reply).toEqual({ code: 400, body });
  });
});

/**
 * LIVE. Needs the node the fixtures were captured from. Opt in with:
 *   MIDNIGHT_PUB_TEST_NODE_URL=ws://127.0.0.1:9944 npx vitest run
 */
const LIVE_NODE_URL = process.env["MIDNIGHT_PUB_TEST_NODE_URL"];

/**
 * ACCEPTANCE. Byte-diffs this handler against the RUST binary this package
 * replaces. Needs the node AND the Rust service; see `tests/state.test.ts` for
 * the read-only invocation that starts the already-built binary on a spare port
 * without rebuilding or modifying that tree.
 */
const RUST_URL = process.env["MIDNIGHT_PUB_TEST_RUST_URL"];

describe.runIf(LIVE_NODE_URL)("live: unwrapping a real block", () => {
  const nodeUrl = LIVE_NODE_URL ?? "";

  it(
    "finds the sendMnTransaction blob and reproduces the Rust binary's body",
    async () => {
      const client = await connect(nodeUrl);
      try {
        const slots = await blockSlots(client, BLOCK_1366);

        // Block 1366 plainly contains a `midnight.sendMnTransaction`. Asserting
        // that one was FOUND is the whole point: `@polkadot/api` camelCases the
        // runtime's `send_mn_transaction`, and matching the snake_case spelling
        // returns an empty block with no error at all.
        const found = slots.filter((slot) => slot.kind === "midnight");
        expect(found.length, "block 1366 must yield a sendMnTransaction blob").toBeGreaterThan(0);

        // The extracted bytes are the fixture's bytes: the unwrapping is exact.
        expect(Buffer.from(found[0]?.bytes ?? new Uint8Array())).toEqual(
          Buffer.from(fixtureTxBytes("notify-tx.mn")),
        );

        const reply = await handleBlock(
          testConfig(nodeUrl),
          client,
          new URL(`/block?hash=${BLOCK_1366}`, "http://localhost"),
        );
        expect(reply.code).toBe(200);
        expect(reply.body).toBe(goldenText("rust-block-1366.json"));
      } finally {
        await client.disconnect();
      }
    },
    120_000,
  );
});

describe.runIf(LIVE_NODE_URL && RUST_URL)("acceptance: /block byte-diff against the Rust binary", () => {
  it(
    "block 1366 is byte-identical",
    async () => {
      const client = await connect(LIVE_NODE_URL ?? "");
      try {
        const query = `/block?hash=${BLOCK_1366}`;
        const rust = await (await fetch(`${RUST_URL ?? ""}${query}`)).text();
        const reply = await handleBlock(
          testConfig(LIVE_NODE_URL ?? ""),
          client,
          new URL(query, "http://localhost"),
        );
        expect(reply.code).toBe(200);
        expect(reply.body).toBe(rust);
      } finally {
        await client.disconnect();
      }
    },
    120_000,
  );
});
