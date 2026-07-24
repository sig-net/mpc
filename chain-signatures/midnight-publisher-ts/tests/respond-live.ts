/**
 * Live acceptance run for `POST /respond`. Deliberately NOT part of
 * `vitest run`: it needs the whole stack up (node, proof server, indexer) and a
 * funded wallet, it costs a real fee, and it writes to the chain.
 *
 *   MIDNIGHT_PUB_NODE_URL=ws://127.0.0.1:9944 \
 *   MIDNIGHT_PUB_PROOF_SERVER_URL=http://127.0.0.1:6300 \
 *   MIDNIGHT_PUB_INDEXER_URL=http://127.0.0.1:8088/api/v3/graphql \
 *   MIDNIGHT_PUB_INDEXER_WS_URL=ws://127.0.0.1:8088/api/v3/graphql/ws \
 *   MIDNIGHT_PUB_MANAGED_DIR=$PWD/node_modules/@sig-net/midnight-contract/dist/managed \
 *   MIDNIGHT_PUB_FUNDING_SEED=<hex> \
 *   npx tsx tests/respond-live.ts <64-hex contract address> [64-hex request id]
 *
 * It drives the real `handleRespond`, so what it exercises is the shipped code
 * path and not a parallel re-implementation. It then establishes three things
 * independently:
 *
 *  - the append landed, by decoding `respondBidirectionalMap` over the node's
 *    runtime API before and after;
 *  - which block it landed in, by walking finalized blocks from the pre-post
 *    head until the map grows;
 *  - the ledger's own apply status, from the indexer, which is the only source
 *    that carries it. `SucceedEntirely` there and the append here are two
 *    independent confirmations of the same fact.
 */

import { randomBytes } from "node:crypto";

import { ContractState } from "@midnight-ntwrk/midnight-js-protocol/compact-runtime";
import { ledger as signetLedger } from "@sig-net/midnight-contract";

import { toHex } from "@midnight-ntwrk/midnight-js-utils";
import { configFromEnv } from "../src/config.js";
import { connect, isHex, runtimeApiBytes, type BlockHashHex, type NodeClient } from "../src/node.js";
import { closePublisher, handleRespond } from "../src/respond.js";

const config = configFromEnv();

const address = process.argv[2] ?? "";
if (!isHex(address, 32)) {
  throw new Error(`usage: tsx tests/respond-live.ts <64-hex contract address> [64-hex request id]`);
}
// A fresh throwaway request id by default, so a re-run never contends with an
// earlier one on the ledger-level optimistic-concurrency check.
const requestId = process.argv[3] ?? toHex(randomBytes(32));
if (!isHex(requestId, 32)) throw new Error(`request id must be 64 lowercase hex, got ${requestId}`);

const client = await connect(config.nodeUrl);

/** The singleton's respond state at one block, read over the runtime API only. */
async function readRespondState(
  at: BlockHashHex,
): Promise<{ size: bigint; counter: bigint | undefined; landed: string[] }> {
  const raw = await runtimeApiBytes(client, at, "getContractState", `0x${address}`);
  if (raw === undefined) throw new Error(`no contract state at ${address} in ${at}`);
  const decoded = signetLedger(ContractState.deserialize(raw).data);
  const key = Uint8Array.from(Buffer.from(requestId, "hex"));
  const landed: string[] = [];
  for (const [entryKey, value] of decoded.respondBidirectionalMap) {
    if (toHex(entryKey.requestId) !== requestId) continue;
    landed.push(
      `count=${entryKey.count} serializedOutput=${toHex(value.serializedOutput).slice(0, 16)}… ` +
        `outputLen=${value.outputLen} bigR.x=${toHex(value.signature.bigR.x).slice(0, 12)}… ` +
        `s=${toHex(value.signature.s).slice(0, 12)}… recoveryId=${value.signature.recoveryId}`,
    );
  }
  return {
    size: decoded.respondBidirectionalMap.size(),
    counter: decoded.respondBidirectionalCounterMap.member(key)
      ? decoded.respondBidirectionalCounterMap.lookup(key).read()
      : undefined,
    landed,
  };
}

async function head(node: NodeClient): Promise<{ hash: BlockHashHex; height: number }> {
  const hash = (await node.rpc.chain.getFinalizedHead()).toHex() as BlockHashHex;
  return { hash, height: (await node.rpc.chain.getHeader(hash)).number.toNumber() };
}

/**
 * The ledger's own apply status. No node RPC carries it, so this is the one
 * place the indexer is read for evidence rather than for fee payment.
 *
 * Asked by block height and matched on the transaction's identifiers, because
 * the root `transactions(offset: {identifier})` query returns nothing for a
 * freshly finalized transaction. `SUCCESS` with no `segments` is the indexer's
 * rendering of the ledger's `SucceedEntirely`; a partial apply reports
 * `PARTIAL_SUCCESS` and populates `segments`.
 *
 * Polled, because the indexer trails the node's finalized head by a few seconds
 * and answers `block: null` until it catches up.
 *
 * Best effort: the append decoded from the runtime API is the primary evidence,
 * and this is an independent second opinion.
 */
async function indexerStatus(height: number, transactionId: string): Promise<string> {
  const query =
    `query BlockStatus($height: Int!) { block(offset: {height: $height}) { transactions { hash __typename ` +
    `... on RegularTransaction { identifiers transactionResult { status segments { id success } } } } } }`;
  const deadline = Date.now() + 60_000;
  let last = "no answer";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(config.indexerUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query, variables: { height } }),
      });
      const payload = (await response.json()) as {
        data?: {
          block?: {
            transactions?: {
              hash: string;
              identifiers?: string[];
              transactionResult?: { status: string; segments: unknown };
            }[];
          } | null;
        };
      };
      const mine = payload.data?.block?.transactions?.find((tx) => tx.identifiers?.includes(transactionId));
      if (mine !== undefined) {
        // SUCCESS with no per-segment breakdown is the indexer's rendering of
        // the ledger's SucceedEntirely; a partial apply reports
        // PARTIAL_SUCCESS and populates segments.
        return (
          `${mine.transactionResult?.status ?? "(no result)"} ` +
          `(segments: ${JSON.stringify(mine.transactionResult?.segments ?? null)})  tx hash ${mine.hash}`
        );
      }
      last = `block ${height} not indexed yet`;
    } catch (error) {
      last = `unavailable (${error instanceof Error ? error.message : String(error)})`;
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  return `${last} after 60 s`;
}

const before = await head(client);
const beforeState = await readRespondState(before.hash);
console.log(`contract        ${address}`);
console.log(`request id      ${requestId}   (fresh, throwaway)`);
console.log(`before          height=${before.height} map.size=${beforeState.size} counter=${beforeState.counter ?? "(absent)"}`);

// A recognisable payload: the request id's first four bytes, then zero padding
// to the full Bytes<128> the event stores.
const serializedOutput = `${requestId.slice(0, 8)}${"00".repeat(124)}`;
const body = JSON.stringify({
  contract_address: address,
  circuit: "postRespondBidirectional",
  request_id: requestId,
  serialized_output: serializedOutput,
  output_len: 4,
  signature: {
    big_r: { x: `${"00".repeat(31)}01`, y: `${"00".repeat(31)}02` },
    s: `${"00".repeat(31)}03`,
    recovery_id: 1,
  },
});

// The handler logs the submitted transaction id; tap it rather than duplicating
// the submit path here, so this script exercises the shipped code and nothing else.
const lines: string[] = [];
const realLog = console.log.bind(console);
console.log = (...args: unknown[]): void => {
  lines.push(args.map((arg) => String(arg)).join(" "));
  realLog(...args);
};

const startedAt = performance.now();
const reply = await handleRespond(config, client, body);
const elapsed = ((performance.now() - startedAt) / 1000).toFixed(2);
console.log = realLog;

console.log(`\nHTTP            ${reply.status} ${reply.body}   (${elapsed} s)`);
if (reply.status !== 200) {
  await closePublisher();
  await client.disconnect();
  throw new Error(`respond did not succeed: ${reply.status} ${reply.body}`);
}

// The success body is wire contract: the submitted transaction id, and the
// finalized block the three reads were pinned to (bare hex). The log line is
// kept only as a cross-check that body and log tell one story.
const success = JSON.parse(reply.body) as { status?: string; tx_id?: string; block_hash?: string };
if (success.status !== "ok" || typeof success.tx_id !== "string" || success.tx_id.length === 0) {
  throw new Error(`the success body must carry a non-empty tx_id: ${reply.body}`);
}
if (typeof success.block_hash !== "string" || !isHex(success.block_hash, 32)) {
  throw new Error(`the success body must carry the pinned block hash as bare 64-hex: ${reply.body}`);
}
const submitted = success.tx_id;
const logged = lines.find((line) => line.includes("submitted tx"))?.split("submitted tx ")[1]?.split(" ")[0];
console.log(`transaction id  ${submitted}${logged === submitted ? "" : `   (LOG DISAGREES: ${logged ?? "(not logged)"})`}`);
console.log(`pinned reads at ${success.block_hash}`);

// Walk finalized blocks forward from the pre-post head until the map grows;
// that block is where the append landed.
let landingHeight: number | undefined;
let landingHash: BlockHashHex | undefined;
for (let height = before.height + 1; landingHeight === undefined; height += 1) {
  const now = await head(client);
  if (height > now.height) {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    height -= 1;
    continue;
  }
  const hash = (await client.rpc.chain.getBlockHash(height)).toHex() as BlockHashHex;
  const state = await readRespondState(hash);
  if (state.size > beforeState.size) {
    landingHeight = height;
    landingHash = hash;
  }
}

const afterState = await readRespondState(landingHash as BlockHashHex);
console.log(`landed in block ${landingHeight} (${landingHash})`);
console.log(`after           map.size=${afterState.size} counter=${afterState.counter ?? "(absent)"}`);
console.log(`map.size        ${beforeState.size} -> ${afterState.size}`);
for (const entry of afterState.landed) console.log(`  entry         ${entry}`);
console.log(`ledger status   ${await indexerStatus(landingHeight, submitted)}`);
console.log(
  afterState.landed.length === 1
    ? `\nRESULT: SUCCEEDED — one append under this request id, confirmed over the runtime API`
    : `\nRESULT: UNEXPECTED — ${afterState.landed.length} appends under this request id`,
);

await closePublisher();
await client.disconnect();
process.exit(0);
