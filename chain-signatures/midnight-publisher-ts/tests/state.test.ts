/**
 * `/state` seam tests.
 *
 * Two tiers, deliberately separated:
 *
 * OFFLINE (always run) — golden tests against committed fixtures. The goldens in
 * `tests/fixtures/rust-*.json` are the VERBATIM response bodies of the Rust
 * `midnight-publisher` binary, captured from the live stack; the `.mn` fixtures
 * are the same contract-state blobs its own test suite uses. Correctness here is
 * anchored to the reference implementation's bytes, not to hand-written
 * expectations.
 *
 * LIVE (opt-in via `MIDNIGHT_PUB_TEST_NODE_URL`) — the parts that need a running
 * node: the anchor wrapper, the finalized-head path, and the full serialized
 * body. See `tests/block.test.ts` for the same split on `/block`.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { StateMap, StateValue, type AlignedValue } from "@midnightntwrk/ledger-v9";
import { ApiPromise, WsProvider } from "@polkadot/api";
import { describe, expect, it } from "vitest";

import type { Config } from "../src/config.js";
import { connect, type NodeClient } from "../src/node.js";
import { decodeContractState, handleState, walk } from "../src/state.js";

/** The deployed singleton and caller of the captured SGN2 flow. Recapture the fixtures and these together. */
const SINGLETON = "aa5d96c2de9af9dfc9fe046c30954a07c32ae1e1c976bf6088f8757d06ff3f47";
const CALLER = "dcd470fbc066befe0b6cddcf273dc9a838832ccbb8327f2625ec7028b0a6f0d2";

/** The notify block and its parent: the pair the whole state-diff design rests on. */
const BLOCK_1365 = "0x1d4c24186a5f3c2ce43c691797bd336aae587e9af29701ed5b532e6aab5dd633";
const BLOCK_1366 = "0x588b87380b6b17463ed87837fa5651a32b5a9d4f02deeb015661f1f04f0ad8fc";

const FIXTURES = fileURLToPath(new URL("./fixtures/", import.meta.url));

function fixtureBytes(name: string): Uint8Array {
  return Uint8Array.from(readFileSync(`${FIXTURES}${name}`));
}

function goldenText(name: string): string {
  return readFileSync(`${FIXTURES}${name}`, "utf8");
}

/**
 * The `tree` member of a golden response as RAW TEXT.
 *
 * Deliberately string surgery rather than `JSON.parse`: round-tripping through a
 * parser launders key order, which is exactly the property under test.
 */
function goldenTree(golden: string): string {
  const marker = ',"tree":';
  const start = golden.indexOf(marker);
  expect(start, "golden must carry a `tree` member").toBeGreaterThan(0);
  expect(golden.endsWith("}")).toBe(true);
  return golden.slice(start + marker.length, -1);
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

/**
 * A real but never-connected client, for the paths that must answer before any
 * network call. `autoConnect: false` means no socket is ever opened, so touching
 * it would hang. That is the point: if validation ever starts reaching the node,
 * these tests stop passing quietly.
 */
const OFFLINE_CLIENT: NodeClient = (() => {
  const provider = new WsProvider("ws://127.0.0.1:1", false);
  return { api: new ApiPromise({ provider, noInitWarn: true }), provider, disconnect: async () => {} };
})();

describe("offline: the decoded tree is byte-identical to the Rust seam's", () => {
  const TREE_GOLDENS: ReadonlyArray<readonly [string, string]> = [
    ["singleton-post-state-1366.mn", "rust-state-singleton-1366.json"],
    ["singleton-pre-state-1365.mn", "rust-state-singleton-1365.json"],
  ];

  it.each(TREE_GOLDENS)("%s matches %s", (fixture, golden) => {
    expect(JSON.stringify(decodeContractState(fixtureBytes(fixture)))).toBe(
      goldenTree(goldenText(golden)),
    );
  });

  it("reproduces the whole response body, key order included", () => {
    // The wrapper's byte layout, pinned against the Rust binary's own output:
    // `anchor` before `tree`, `height` before `hash`, hash bare with no `0x`.
    const tree = JSON.stringify(decodeContractState(fixtureBytes("singleton-post-state-1366.mn")));
    expect(`{"anchor":{"height":1366,"hash":"${BLOCK_1366.slice(2)}"},"tree":${tree}}`).toBe(
      goldenText("rust-state-singleton-1366.json"),
    );
  });
});

describe("offline: the schema the consumer parses", () => {
  it("tags every node on `kind`, serialized first", () => {
    const tree = decodeContractState(fixtureBytes("reference-state.mn"));
    expect(tree.kind).toBe("array");
    // `kind` must serialize FIRST: the consumer's discriminated-union parser and
    // the byte-diff both depend on it.
    expect(JSON.stringify(tree).startsWith('{"kind":"array","children":[')).toBe(true);
  });

  it("extracts trailing-zero-trimmed atoms in declaration order", () => {
    const tree = decodeContractState(fixtureBytes("reference-state.mn"));
    if (tree.kind !== "array") throw new Error(`reference state is an ordinal array, got ${tree.kind}`);

    // Ordinal 0 is the configured hub contract address; ordinal 1 is the MPC
    // attestation Secp256k1Point. Both are independent oracles: they match the
    // cross-language golden state-fixture that `chain-midnight` parses, which is
    // what proves the trimmed, declaration-order atom extraction.
    expect(tree.children[0]).toEqual({
      kind: "cell",
      atoms: ["1ff6b01828eaff69181037f78de6ef97fb4e179c082302633f6f99c39790c476"],
    });
    expect(tree.children[1]).toEqual({
      kind: "cell",
      atoms: [
        "c54fb75de1cf50d52c6aa024b979dcbcf11306595fa23489",
        "430667daa96f76bd",
        "aaa4d27b044ee6320f8d8269caebba009de81c8d143d4ade",
        "cb49972244d665fe",
        "",
      ],
    });
    // Ordinals 3 & 4 are the signBiRequests / signRequests maps.
    expect(tree.children[3]?.kind).toBe("map");
    expect(tree.children[4]?.kind).toBe("map");
  });

  it("sorts map entries by key hex", () => {
    // The live signet maps hold one entry, so the ordering rule is exercised on a
    // synthetic map walked through the real decoder, inserted out of order.
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
    expect(node.entries.map((entry) => entry.key)).toEqual(["01", "02", "03"]);
  });
});

describe("offline: validation answers before any network call", () => {
  // Every message here is the Rust binary's verbatim 400 body: `chain-midnight`
  // must not be able to tell which implementation answered it.
  const REJECTED: ReadonlyArray<readonly [string, string]> = [
    ["/state", "missing `address` query param"],
    ["/state?address=zz", "address must be 64 lowercase hex"],
    [`/state?address=${SINGLETON.slice(0, 63)}`, "address must be 64 lowercase hex"],
    [`/state?address=${SINGLETON.toUpperCase()}`, "address must be 64 lowercase hex"],
    [`/state?address=${SINGLETON}&at=0xzz`, "at must be `0x` followed by 64 lowercase hex"],
    [
      `/state?address=${SINGLETON}&at=${BLOCK_1366.slice(2)}`,
      "at must be `0x` followed by 64 lowercase hex",
    ],
  ];

  it.each(REJECTED)("%s -> 400", async (path, body) => {
    const reply = await handleState(
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
 * ACCEPTANCE. Byte-diffs these handlers against the RUST binary this package
 * replaces, live, on both seams. Needs the node AND the Rust service; opt in
 * with `MIDNIGHT_PUB_TEST_RUST_URL`.
 *
 * The Rust tree is not rebuilt and not modified — the already-built binary is
 * run read-only on a spare port with throwaway credentials, since the read seams
 * never touch the toolkit, the wallet or the signer:
 *
 *   cd ../midnight-publisher && \
 *   MIDNIGHT_PUB_PORT=8799 MIDNIGHT_PUB_NODE_URL=ws://127.0.0.1:9944 \
 *   MIDNIGHT_PUB_WORK_DIR=/tmp/mnpub-ref MIDNIGHT_PUB_TOOLKIT_BIN=/bin/false \
 *   MIDNIGHT_PUB_FUNDING_SEED=throwaway MIDNIGHT_PUB_COIN_PUBLIC=00 \
 *   MIDNIGHT_PUB_SIGNER_SECRET_KEY=00 ./target/debug/midnight-publisher &
 *
 *   MIDNIGHT_PUB_TEST_NODE_URL=ws://127.0.0.1:9944 \
 *   MIDNIGHT_PUB_TEST_RUST_URL=http://127.0.0.1:8799 npx vitest run
 *
 *   kill %1
 */
const RUST_URL = process.env["MIDNIGHT_PUB_TEST_RUST_URL"];

describe.runIf(LIVE_NODE_URL)("live: anchored reads against the node", () => {
  const nodeUrl = LIVE_NODE_URL ?? "";

  async function stateBody(client: NodeClient, query: string): Promise<string> {
    const reply = await handleState(
      testConfig(nodeUrl),
      client,
      new URL(`/state?${query}`, "http://localhost"),
    );
    expect(reply.code).toBe(200);
    return reply.body;
  }

  it(
    "serves both contracts at a pinned `at` byte-identically to the Rust binary",
    async () => {
      const client = await connect(nodeUrl);
      try {
        expect(await stateBody(client, `address=${SINGLETON}&at=${BLOCK_1366}`)).toBe(
          goldenText("rust-state-singleton-1366.json"),
        );
        expect(await stateBody(client, `address=${CALLER}&at=${BLOCK_1366}`)).toBe(
          goldenText("rust-state-caller-1366.json"),
        );
        expect(await stateBody(client, `address=${SINGLETON}&at=${BLOCK_1365}`)).toBe(
          goldenText("rust-state-singleton-1365.json"),
        );
      } finally {
        await client.disconnect();
      }
    },
    120_000,
  );

  it(
    "raises a DISTINCT error when a read is refused on a block it can still fetch",
    async () => {
      // The §3.1 finding, asserted on the live node's own error taxonomy. Both
      // failure modes return -32602 with no `data`, so only the text separates
      // "this contract did not exist yet" from "this node has lost the ability
      // to answer". An archive node answers `ContractNotPresent` here, which is
      // POSITIVE evidence that state at that height was reachable, so the seam
      // must NOT report pruning. On a pruned node the same call yields the
      // catch-all and the seam must say so loudly instead.
      const client = await connect(nodeUrl);
      try {
        const absent = handleState(
          testConfig(nodeUrl),
          client,
          new URL(`/state?address=${"00".repeat(32)}&at=${BLOCK_1366}`, "http://localhost"),
        );
        await expect(absent).rejects.toThrow(/not present/i);
        await expect(absent).rejects.not.toThrow(/PRUNED/);
      } finally {
        await client.disconnect();
      }
    },
    120_000,
  );

  it(
    "anchors to the finalized head when no `at` is given",
    async () => {
      const client = await connect(nodeUrl);
      try {
        const observed = (
          await client.api.rpc.chain.getHeader(await client.api.rpc.chain.getFinalizedHead())
        ).number.toNumber();
        const body = await stateBody(client, `address=${SINGLETON}`);

        // Asserted on the raw text, so the wrapper's byte layout is pinned by a
        // LIVE response and not only by the committed goldens. The head advances
        // every 6s, so the height is bounded rather than fixed.
        const anchor = /^\{"anchor":\{"height":(\d+),"hash":"([0-9a-f]{64})"\},"tree":\{/.exec(body);
        expect(anchor, `unexpected anchor layout: ${body.slice(0, 120)}`).not.toBeNull();
        expect(Number(anchor?.[1])).toBeGreaterThanOrEqual(observed);
      } finally {
        await client.disconnect();
      }
    },
    120_000,
  );
});

describe.runIf(LIVE_NODE_URL && RUST_URL)("acceptance: /state byte-diff against the Rust binary", () => {
  const nodeUrl = LIVE_NODE_URL ?? "";
  const rustUrl = RUST_URL ?? "";

  async function bothBodies(query: string): Promise<[string, string]> {
    const client = await connect(nodeUrl);
    try {
      const rust = await (await fetch(`${rustUrl}${query}`)).text();
      const reply = await handleState(testConfig(nodeUrl), client, new URL(query, "http://localhost"));
      expect(reply.code).toBe(200);
      return [rust, reply.body];
    } finally {
      await client.disconnect();
    }
  }

  it.each([
    [`/state?address=${SINGLETON}&at=${BLOCK_1366}`],
    [`/state?address=${CALLER}&at=${BLOCK_1366}`],
    [`/state?address=${SINGLETON}&at=${BLOCK_1365}`],
  ])("%s is byte-identical", async (query) => {
    const [rust, ts] = await bothBodies(query);
    expect(ts).toBe(rust);
  }, 120_000);

  it(
    "is byte-identical at the finalized head",
    async () => {
      // Both services resolve the head independently, so they can land on
      // different blocks if one lands either side of a 6s block. Retried until
      // they agree on the anchor; only then is the comparison meaningful.
      const client = await connect(nodeUrl);
      try {
        const query = `/state?address=${SINGLETON}`;
        let rust = "";
        let ts = "";
        for (let attempt = 0; attempt < 5; attempt++) {
          rust = await (await fetch(`${rustUrl}${query}`)).text();
          ts = (await handleState(testConfig(nodeUrl), client, new URL(query, "http://localhost")))
            .body;
          if (rust.slice(0, 90) === ts.slice(0, 90)) break;
        }
        expect(ts, "the two services never agreed on a finalized head").toBe(rust);
      } finally {
        await client.disconnect();
      }
    },
    120_000,
  );
});
