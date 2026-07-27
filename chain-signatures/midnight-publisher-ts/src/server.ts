// The localhost HTTP seam.
//
// GET  /health                  -> {status, networkId, ledger}
// POST /decode/contract-state   {state: hex}          -> the state tree
// POST /decode/transactions     {transactions: [hex]} -> {transactions, skipped}
// POST /respond                 -> {status, tx_id, block_hash}
//
// The decode seams are POST only because a serialized transaction runs ~14 KB
// and does not fit a query string.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { isDeserializationError } from "@midnight-ntwrk/midnight-js-utils";

import { type Config } from "./config.js";
import { fail, jsonObject, PublisherError, replyTo, type ErrorCode, type Reply } from "./errors.js";
import { LEDGER_TAGS } from "./ledger.js";
import { fromHex, type NodeClient } from "./node.js";
import { decodeTransactions } from "./block.js";
import { handleRespond } from "./respond.js";
import { decodeContractState } from "./state.js";

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request as AsyncIterable<Buffer>) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

// ONE spelling, matching `respond.ts` and what the Rust caller sends: bare, even
// length, lowercase. Accepting `0x` and upper case too would mean two renderings
// of one blob, and `Buffer.from(_, "hex")` truncates silently at the first bad
// character, so a rejected spelling is the only way a caller learns it guessed.
const BARE_LOWERCASE_HEX = /^(?:[0-9a-f]{2})+$/;

function hexBytes(value: unknown, what: string): Uint8Array {
  if (typeof value !== "string") throw new PublisherError("bad_request", `${what} must be a hex string`);
  if (!BARE_LOWERCASE_HEX.test(value)) {
    throw new PublisherError("bad_request", `${what} must be non-empty bare lowercase hex, no \`0x\` prefix`);
  }
  return fromHex(value);
}

function hexList(value: unknown, what: string): Uint8Array[] {
  if (!Array.isArray(value)) throw new PublisherError("bad_request", `\`${what}\` must be an array of hex strings`);
  return value.map((item: unknown, index) => hexBytes(item, `\`${what}[${index}]\``));
}

// The library reports `version-mismatch` for any bad tag, so a RECEIVED version is the real evidence.
function decodeFailureCode(error: unknown): ErrorCode {
  const skewed = isDeserializationError(error) && error.context.extracted?.receivedVersion !== undefined;
  return skewed && error.context.classification === "version-mismatch" ? "ledger_mismatch" : "decode_failed";
}

// `onFatal` runs only after a `fatal` reply is flushed: the caller must learn its post may still land.
export function buildServer(config: Config, client: NodeClient, onFatal?: () => void): Server {
  // Deliberately liveness, not readiness.
  const healthBody = JSON.stringify({ status: "ok", networkId: config.networkId, ledger: LEDGER_TAGS });

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
