/**
 * Recaptures the raw chain fixtures in this directory from the running local stack.
 * THIS SCRIPT IS THE FIXTURES' PROVENANCE: each file below is whatever it
 * writes, nothing else. Run it with the midnight-integration stack up:
 *
 *   npx tsx tests/fixtures/regenerate.ts
 *
 * The `.mn` files are raw chain data (contract-state blobs and transaction
 * bytes) read off the node. Goldens are NOT written here: the decoders that
 * produce them live in Rust, so a golden is regenerated from `chain-midnight`
 * and this script captures only the bytes a golden is derived from.
 *
 * Chain identity is asserted first: the pinned heights and addresses only mean
 * anything on the chain they were captured from. On a fresh chain, redeploy,
 * update the constants, and recapture.
 */

// STALE CONSTANTS: the genesis, addresses and heights below still name the retired
// 0.11-era capture chain. Before the next capture, re-point them at the storage-line
// deploy (contract @sig-net/* 0.15.0, release commit b270880) and a block holding a
// landed respond. The refusal-to-run guard is the point: it must keep refusing until
// someone re-points it deliberately.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { ApiPromise, WsProvider } from "@polkadot/api";

const HERE = fileURLToPath(new URL("./", import.meta.url));

/** The capture chain, and what lives where on it. */
const GENESIS = "0xbbb72bbbb3f32d2f2ffe1194d09c301ae167a804eda089c433cb76a4ac4e6cbb";
const SINGLETON = "aa5d96c2de9af9dfc9fe046c30954a07c32ae1e1c976bf6088f8757d06ff3f47";
const NOTIFY_HEIGHT = 1366;

const provider = new WsProvider(process.env["MIDNIGHT_NODE_URL"] ?? "ws://127.0.0.1:9944");
const api = await ApiPromise.create({ provider, noInitWarn: true });

const hashAt = async (height: number): Promise<string> => (await api.rpc.chain.getBlockHash(height)).toHex();

const genesis = await hashAt(0);
if (genesis !== GENESIS) {
  throw new Error(`this node's genesis is ${genesis}, not the capture chain's ${GENESIS}; see the header before recapturing`);
}

function write(name: string, fresh: Buffer): void {
  const path = `${HERE}${name}`;
  const previous = existsSync(path) ? readFileSync(path) : undefined;
  const status = previous === undefined ? "created" : previous.equals(fresh) ? "unchanged" : "CHANGED";
  writeFileSync(path, fresh);
  console.log(`${status.padEnd(9)} ${name} (${fresh.length}B)`);
}

/** A contract's raw `contract-state[v8]` blob at a pinned height. */
async function stateBlob(address: string, height: number): Promise<Buffer> {
  const blob = (await provider.send("midnight_contractState", [address, await hashAt(height)])) as string;
  return Buffer.from(blob.replace(/^0x/, ""), "hex");
}

/** A block's one `midnight.sendMnTransaction` argument, bare ledger-transaction bytes. */
async function onlyTxBytes(height: number): Promise<Buffer> {
  const block = await api.rpc.chain.getBlock(await hashAt(height));
  const txs = block.block.extrinsics.filter((xt) => xt.method.section === "midnight" && xt.method.method === "sendMnTransaction");
  if (txs.length !== 1) throw new Error(`block ${height} carries ${txs.length} midnight transactions, expected exactly 1`);
  return Buffer.from(txs[0]!.method.args[0]!.toU8a(true));
}

/** The `RawTransaction` JSON wrapper the transaction fixtures use. */
const txFixture = (bytes: Buffer): Buffer => Buffer.from(JSON.stringify({ tx: { Midnight: bytes.toString("hex") } }));

const preState = await stateBlob(SINGLETON, NOTIFY_HEIGHT - 1);
const postState = await stateBlob(SINGLETON, NOTIFY_HEIGHT);
const notifyTx = await onlyTxBytes(NOTIFY_HEIGHT);

write(`singleton-pre-state-${NOTIFY_HEIGHT - 1}.mn`, preState);
write(`singleton-post-state-${NOTIFY_HEIGHT}.mn`, postState);
write(`notify-tx.mn`, txFixture(notifyTx));

const head = (await api.rpc.chain.getHeader()).number.toString();
await api.disconnect();
console.log(`regenerated from chain ${genesis} at height ${head}`);
process.exit(0);
