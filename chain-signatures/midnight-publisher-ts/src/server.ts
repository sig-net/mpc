/**
 * The localhost HTTP seam.
 *
 *   GET  /health                  -> {status, networkId, ledger}
 *   POST /decode/contract-state   {state: hex}          -> the state tree
 *   POST /decode/transactions     {transactions: [hex]} -> {transactions, skipped}
 *   POST /respond                 -> {status, tx_id, block_hash}
 *
 * The decode seams are pure codecs and open no connection. They are POST only
 * because a serialized transaction runs ~14 KB and does not fit a query string.
 * Every failure is `{code, message}`; see `errors.ts`.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { isDeserializationError, isHex as isWholeBytesHex } from "@midnight-ntwrk/midnight-js-utils";

import { type Config } from "./config.js";
import { fail, jsonObject, PublisherError, replyTo, type ErrorCode, type Reply } from "./errors.js";
import { LEDGER_TAGS } from "./ledger.js";
import { fromHex, type NodeClient } from "./node.js";
import { decodeTransactions } from "./block.js";
import { handleRespond } from "./respond.js";
import { decodeContractState } from "./state.js";

/**
 * Read unbounded: the only caller is the trusted in-node publisher over
 * loopback, so there is no body-size cap to enforce here.
 */
async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request as AsyncIterable<Buffer>) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Checked with the library's whole-bytes `isHex` (optional `0x`, any case,
 * non-empty), not coerced: `Buffer.from(_, "hex")` truncates silently at the
 * first bad character, which would hand the ledger a short blob and blame the
 * caller's bytes (`decode_failed`) for an envelope mistake (`bad_request`).
 */
function hexBytes(value: unknown, what: string): Uint8Array {
  if (typeof value !== "string") throw new PublisherError("bad_request", `${what} must be a hex string`);
  if (!isWholeBytesHex(value)) throw new PublisherError("bad_request", `${what} must be a whole number of bytes of hex, optionally \`0x\`-prefixed`);
  return fromHex(value);
}

/** The envelope fails the whole request; only bytes the LEDGER refuses survive per item. */
function hexList(value: unknown, what: string): Uint8Array[] {
  if (!Array.isArray(value)) throw new PublisherError("bad_request", `\`${what}\` must be an array of hex strings`);
  return value.map((item: unknown, index) => hexBytes(item, `\`${what}[${index}]\``));
}

/**
 * Classification alone cannot separate a version skew from garbage: the library
 * reports `version-mismatch` for any unexpected header tag, `deadbeef` included.
 * A RECEIVED version is the evidence the chain moved.
 */
function decodeFailureCode(error: unknown): ErrorCode {
  const skewed = isDeserializationError(error) && error.context.extracted?.receivedVersion !== undefined;
  return skewed && error.context.classification === "version-mismatch" ? "ledger_mismatch" : "decode_failed";
}

/**
 * `onFatal` runs after a {@link Reply} marked `fatal` has been flushed, which is
 * the only safe point to stop: the caller must learn its post may still land.
 */
export function buildServer(config: Config, client: NodeClient, onFatal?: () => void): Server {
  /** Liveness plus the compatibility declaration (ledger line, network id). Deliberately not readiness. */
  const healthBody = JSON.stringify({ status: "ok", networkId: config.networkId, ledger: LEDGER_TAGS });

  /**
   * The envelope is the caller's, the bytes are the ledger's.
   *
   * `field` names the body key per route rather than sharing one generic name:
   * the two seams take semantically different payloads (one state blob against
   * a list of transactions), so a shared `bytes` made the list read as a blob
   * and put both routes one silent typo away from each other.
   */
  const decode = async (request: IncomingMessage, field: string, seam: (value: unknown) => unknown): Promise<Reply> => {
    const text = await readBody(request);
    try {
      return { status: 200, body: JSON.stringify(seam(jsonObject(text)[field])) };
    } catch (error) {
      return replyTo(error, "decode failed", decodeFailureCode(error));
    }
  };

  const handle = async (request: IncomingMessage): Promise<Reply> => {
    const route = `${request.method ?? "GET"} ${new URL(request.url ?? "/", "http://localhost").pathname}`;

    switch (route) {
      case "GET /health":
        return { status: 200, body: healthBody };
      case "POST /decode/contract-state":
        return decode(request, "state", (v) => decodeContractState(hexBytes(v, "`state`")));
      case "POST /decode/transactions":
        return decode(request, "transactions", (v) => decodeTransactions(hexList(v, "transactions")));
      case "POST /respond":
        return handleRespond(config, client, await readBody(request));
      default:
        return fail("not_found", `no route ${route}`);
    }
  };

  /** One request, one reply: `handle` decides it, this writes it. */
  const answer = async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    // Reached in normal operation: `readBody` rejects with `aborted` when a
    // client hangs up mid-body, so this catch includes disconnects.
    const reply = await handle(request).catch((error: unknown) => replyTo(error, "unhandled"));
    const stop = reply.fatal === true ? onFatal : undefined;
    response.writeHead(reply.status, { "content-type": "application/json" }).end(reply.body, stop);
  };

  return createServer((request, response) => void answer(request, response));
}

export async function serve(config: Config, client: NodeClient, onFatal?: () => void): Promise<Server> {
  const server = buildServer(config, client, onFatal);
  await new Promise<void>((resolve, reject) => server.once("error", reject).listen(config.port, config.bindHost, resolve));
  console.log(`midnight-publisher listening on ${config.bindHost}:${config.port}`);
  return server;
}
