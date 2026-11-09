import { afterEach, describe, expect, it, vi } from "vitest";

import { PublisherError } from "../src/errors.js";
import { FIRST_LOOK_MS, locate, LOOK_EVERY_MS, watchLanding, type Rpc } from "../src/landing.js";

const TX = "c0ffee";
const TX_ID = "ab".repeat(32);

// A node with a ready pool and a chain of blocks, each a list of extrinsic hex strings.
function node(chain: { pool: string[]; blocks: string[][]; finalized: number }) {
  const calls: string[] = [];
  let down = false;
  const rpc: Rpc = async (method, params) => {
    calls.push(method);
    if (down) throw new TypeError("fetch failed");
    const header = (height: number) => ({ number: `0x${height.toString(16)}` });
    switch (method) {
      case "author_pendingExtrinsics":
        return chain.pool;
      case "chain_getFinalizedHead":
        return `0xf${chain.finalized}`;
      case "chain_getHeader": {
        const [hash] = params as [string | undefined];
        return header(hash === undefined ? chain.blocks.length - 1 : chain.finalized);
      }
      case "chain_getBlockHash":
        return `0xb${String(params[0])}`;
      case "chain_getBlock": {
        const height = Number(String(params[0]).slice(3));
        return { block: { extrinsics: chain.blocks[height] } };
      }
      default:
        throw new Error(`unexpected ${method}`);
    }
  };
  return {
    rpc,
    calls,
    chain,
    setDown: (value: boolean) => {
      down = value;
    },
  };
}

const extrinsic = (payload: string) => `0x0405${payload}`;

afterEach(() => {
  vi.useRealTimers();
});

describe("locate", () => {
  it("finds the transaction in the pool, a final block or an unfinal one, or nowhere", async () => {
    const empty = [extrinsic("aa")];
    const scanned = () => ({ finalizedUpTo: -1 });
    const pooled = node({ pool: [extrinsic(`00${TX}00`)], blocks: [empty], finalized: 0 });
    await expect(locate(pooled.rpc, TX, 0, scanned())).resolves.toBe("pending");

    const final = node({ pool: [], blocks: [empty, [extrinsic(TX)], empty], finalized: 1 });
    await expect(locate(final.rpc, TX, 0, scanned())).resolves.toBe("finalized");

    const unfinal = node({ pool: [], blocks: [empty, empty, [extrinsic(TX)]], finalized: 1 });
    await expect(locate(unfinal.rpc, TX, 0, scanned())).resolves.toBe("pending");

    const nowhere = node({ pool: [extrinsic("bb")], blocks: [empty, empty], finalized: 1 });
    await expect(locate(nowhere.rpc, TX, 0, scanned())).resolves.toBe("absent");
  });

  it("searches only from the start height, and final blocks once", async () => {
    const empty = [extrinsic("aa")];
    // Below the start height, so not this submit's transaction.
    const chain = node({ pool: [], blocks: [[extrinsic(TX)], empty, empty, empty], finalized: 2 });
    const scanned = { finalizedUpTo: -1 };

    await expect(locate(chain.rpc, TX, 1, scanned)).resolves.toBe("absent");
    expect(scanned.finalizedUpTo).toBe(2);
    expect(chain.calls.filter((call) => call === "chain_getBlock")).toHaveLength(3);

    chain.calls.length = 0;
    await locate(chain.rpc, TX, 1, scanned);
    // Only block 3, which was not final.
    expect(chain.calls.filter((call) => call === "chain_getBlock")).toHaveLength(1);
  });

  it("does not say when the node does not answer or answers nonsense", async () => {
    const down = node({ pool: [], blocks: [[]], finalized: 0 });
    down.setDown(true);
    await expect(locate(down.rpc, TX, 0, { finalizedUpTo: -1 })).resolves.toBe("unknown");

    const odd = node({ pool: ["not hex"] as string[], blocks: [[]], finalized: 0 });
    await expect(locate(odd.rpc, TX, 0, { finalizedUpTo: -1 })).resolves.toBe("unknown");
  });
});

describe("watchLanding", () => {
  it("answers not_submitted three blocks in when the node holds the transaction nowhere", async () => {
    vi.useFakeTimers();
    const chain = node({ pool: [], blocks: [[], []], finalized: 1 });
    const watch = watchLanding(chain.rpc, TX, TX_ID);
    const verdict = watch.verdict.catch((error: unknown) => error);

    await vi.advanceTimersByTimeAsync(FIRST_LOOK_MS - 1);
    expect(chain.calls).not.toContain("author_pendingExtrinsics");
    await vi.advanceTimersByTimeAsync(1);

    const refusal = await verdict;
    expect(refusal).toBeInstanceOf(PublisherError);
    expect(refusal).toMatchObject({
      code: "not_submitted",
      message: expect.stringMatching(/neither in its pool nor in a block.*retry is safe/),
    });
  });

  it("keeps waiting while the transaction is pending, and lands once it is final", async () => {
    vi.useFakeTimers();
    const chain = node({ pool: [extrinsic(TX)], blocks: [[]], finalized: 0 });
    const watch = watchLanding(chain.rpc, TX, TX_ID);
    let settled = false;
    void watch.verdict.then(() => (settled = true));

    await vi.advanceTimersByTimeAsync(FIRST_LOOK_MS + 3 * LOOK_EVERY_MS);
    expect(settled).toBe(false);

    chain.chain.pool = [];
    chain.chain.blocks.push([extrinsic(TX)]);
    await vi.advanceTimersByTimeAsync(LOOK_EVERY_MS);
    expect(settled).toBe(false);

    chain.chain.finalized = 1;
    await vi.advanceTimersByTimeAsync(LOOK_EVERY_MS);
    await expect(watch.verdict).resolves.toBe(TX_ID);
  });

  it("keeps waiting while the node does not answer, then judges from the time since", async () => {
    vi.useFakeTimers();
    const chain = node({ pool: [], blocks: [[]], finalized: 0 });
    chain.setDown(true);
    const watch = watchLanding(chain.rpc, TX, TX_ID);
    let settled = false;
    void watch.verdict.then(
      () => (settled = true),
      () => (settled = true),
    );

    // A minute of outage, during which the chain grew by ten blocks and took the transaction.
    await vi.advanceTimersByTimeAsync(60_000);
    expect(settled).toBe(false);
    for (let height = 1; height <= 10; height += 1) {
      chain.chain.blocks.push(height === 4 ? [extrinsic(TX)] : []);
    }
    chain.chain.finalized = 10;
    chain.setDown(false);

    await vi.advanceTimersByTimeAsync(LOOK_EVERY_MS);
    await expect(watch.verdict).resolves.toBe(TX_ID);
  });

  it("stops looking once stopped", async () => {
    vi.useFakeTimers();
    const chain = node({ pool: [], blocks: [[]], finalized: 0 });
    const watch = watchLanding(chain.rpc, TX, TX_ID);
    let settled = false;
    void watch.verdict.then(
      () => (settled = true),
      () => (settled = true),
    );

    watch.stop();
    await vi.advanceTimersByTimeAsync(FIRST_LOOK_MS + LOOK_EVERY_MS);

    expect(settled).toBe(false);
    expect(chain.calls).toEqual(["chain_getHeader"]);
  });
});
