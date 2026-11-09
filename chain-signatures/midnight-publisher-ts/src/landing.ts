// Where a submitted transaction is, asked of the node over plain JSON-RPC: the SDK learns it
// only from its `submitAndWatch` subscription, which a dropped or frozen node socket ends
// without an answer.

import { PublisherError } from "./errors.js";

const RPC_TIMEOUT_MS = 3_000;

export type Whereabouts =
  /** In a block at or below the finalized head. */
  | "finalized"
  /** In the node's ready pool, or in a block not yet finalized. */
  | "pending"
  /** In neither, as of an answer from the node. */
  | "absent"
  /** The node did not answer. */
  | "unknown";

export type Rpc = (method: string, params: readonly unknown[]) => Promise<unknown>;

export function nodeRpc(nodeUrl: string): Rpc {
  return async (method, params) => {
    const response = await fetch(nodeUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
    });
    const body = (await response.json()) as { result?: unknown; error?: unknown };
    if (!response.ok || body.error !== undefined || !("result" in body)) {
      throw new Error(`${method} failed: ${JSON.stringify(body.error ?? response.status)}`);
    }
    return body.result;
  };
}

function hexOf(value: unknown): string {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]*$/.test(value)) {
    throw new Error(`expected hex, got ${JSON.stringify(value)}`);
  }
  return value.slice(2).toLowerCase();
}

function heightOf(header: unknown): number {
  const number = (header as { number?: unknown } | null)?.number;
  const height = Number.parseInt(hexOf(number), 16);
  if (!Number.isSafeInteger(height)) throw new Error(`unreadable block number ${String(number)}`);
  return height;
}

export async function bestHeight(rpc: Rpc): Promise<number> {
  return heightOf(await rpc("chain_getHeader", []));
}

/**
 * Looks for the extrinsic carrying `txHex` (the serialized transaction, lowercase, no `0x`)
 * in the ready pool and then in blocks `fromHeight` to the best block, in that order so a
 * transaction leaving the pool for a block between the two reads is still found. Blocks up
 * to `scanned.finalizedUpTo` were searched before and are final, so they are skipped.
 */
export async function locate(
  rpc: Rpc,
  txHex: string,
  fromHeight: number,
  scanned: { finalizedUpTo: number },
): Promise<Whereabouts> {
  try {
    const pool = await rpc("author_pendingExtrinsics", []);
    if (!Array.isArray(pool)) throw new Error("author_pendingExtrinsics returned no list");
    if (pool.some((extrinsic) => hexOf(extrinsic).includes(txHex))) return "pending";
    const finalized = heightOf(
      await rpc("chain_getHeader", [await rpc("chain_getFinalizedHead", [])]),
    );
    const best = await bestHeight(rpc);
    for (
      let height = Math.max(fromHeight, scanned.finalizedUpTo + 1);
      height <= best;
      height += 1
    ) {
      const hash = await rpc("chain_getBlockHash", [height]);
      const block = (await rpc("chain_getBlock", [hash])) as {
        block?: { extrinsics?: unknown };
      } | null;
      const extrinsics = block?.block?.extrinsics;
      if (!Array.isArray(extrinsics)) throw new Error(`block ${height} has no extrinsics list`);
      if (extrinsics.some((extrinsic) => hexOf(extrinsic).includes(txHex))) {
        return height <= finalized ? "finalized" : "pending";
      }
      if (height <= finalized) scanned.finalizedUpTo = height;
    }
    return "absent";
  } catch {
    return "unknown";
  }
}

// About three blocks: a transaction the node accepted is in its pool or a block by then.
export const FIRST_LOOK_MS = 18_000;
export const LOOK_EVERY_MS = 6_000;
// The start height is read before submitting; when the node did not answer then, blocks
// are searched back over the time since, at a block every three seconds or slower.
const SLOWEST_BLOCK_MS = 3_000;

export interface Watch {
  /**
   * Resolves with `txId` once the transaction is final, rejects with `not_submitted` once
   * the node answers that it holds it nowhere, and otherwise stays pending.
   */
  readonly verdict: Promise<string>;
  stop(): void;
}

export function watchLanding(rpc: Rpc, txHex: string, txId: string): Watch {
  const startedMs = Date.now();
  let fromHeight: number | undefined;
  void bestHeight(rpc).then(
    (height) => void (fromHeight ??= height),
    () => undefined,
  );
  const scanned = { finalizedUpTo: -1 };
  let timer: NodeJS.Timeout | undefined;
  let stopped = false;
  const verdict = new Promise<string>((resolve, reject) => {
    const look = async (): Promise<void> => {
      if (fromHeight === undefined) {
        const best = await bestHeight(rpc).catch(() => undefined);
        if (best !== undefined) {
          const blocks = Math.ceil((Date.now() - startedMs) / SLOWEST_BLOCK_MS);
          fromHeight = Math.max(0, best - blocks - 1);
        }
      }
      if (stopped) return;
      const where =
        fromHeight === undefined ? "unknown" : await locate(rpc, txHex, fromHeight, scanned);
      if (stopped) return;
      if (where === "finalized") return resolve(txId);
      if (where === "absent") {
        return reject(
          new PublisherError(
            "not_submitted",
            `the node holds transaction ${txId} neither in its pool nor in a block ` +
              `${((Date.now() - startedMs) / 1_000).toFixed(1)}s after submitting; ` +
              `retry is safe; should this attempt still reach the node, the response may post twice, ` +
              `which is safe`,
          ),
        );
      }
      timer = setTimeout(() => void look(), LOOK_EVERY_MS);
    };
    timer = setTimeout(() => void look(), FIRST_LOOK_MS);
  });
  return {
    verdict,
    stop() {
      stopped = true;
      clearTimeout(timer);
    },
  };
}
