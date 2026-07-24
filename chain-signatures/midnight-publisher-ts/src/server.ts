/**
 * The localhost HTTP seam.
 *
 *   GET  /health                  -> {status, ledger}
 *   POST /decode/contract-state   -> the state tree
 *   POST /decode/transactions     -> {transactions, skipped}
 *   POST /respond                 -> {"status":"ok"}
 *
 * The decode seams are pure codecs and open no connection. They are POST only
 * because a serialized transaction runs ~14 KB and does not fit a query string.
 * Every failure is `{"code","message"}`; see `errors.ts`.
 */

import { createServer, type IncomingMessage, type Server } from "node:http";

import { isDeserializationError } from "@midnight-ntwrk/midnight-js-utils";

import { type Config } from "./config.js";
import { badRequest, failRedacted, jsonObject, PublisherError, type ErrorCode, type Reply } from "./errors.js";
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
 * Checked, not coerced: `Buffer.from(_, "hex")` truncates silently at the first
 * non-hex character, which would hand the ledger a short blob and blame the
 * caller's bytes for it — a caller-side hex bug must answer `bad_request`
 * ("fix the request"), never `decode_failed` ("inspect the blob").
 */
function hexBytes(value: unknown, what: string): Uint8Array {
  if (typeof value !== "string") throw badRequest(`${what} must be a hex string`);
  const hex = value.startsWith("0x") ? value.slice(2) : value;
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw badRequest(`${what} must be a whole number of bytes of hex, optionally \`0x\`-prefixed`);
  }
  return fromHex(hex);
}

/** The envelope fails the whole request; only bytes the LEDGER refuses survive per item. */
function hexList(value: unknown): Uint8Array[] {
  if (!Array.isArray(value)) throw badRequest("`bytes` must be an array of hex strings");
  return value.map((item: unknown, index) => hexBytes(item, `\`bytes[${index}]\``));
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

export function buildServer(config: Config, client: NodeClient): Server {
  /** Liveness plus the compatibility declaration (ledger line, network id). Deliberately not readiness. */
  const healthBody = JSON.stringify({ status: "ok", networkId: config.networkId, ledger: LEDGER_TAGS });

  /** The envelope is the caller's, the bytes are the ledger's. */
  const decode = async (request: IncomingMessage, seam: (bytes: unknown) => unknown): Promise<Reply> => {
    const text = await readBody(request);
    try {
      return { status: 200, body: JSON.stringify(seam(jsonObject(text)["bytes"])) };
    } catch (error) {
      const code = error instanceof PublisherError ? error.code : decodeFailureCode(error);
      return failRedacted(code, error instanceof Error ? error.message : String(error), [config.fundingSeed], "decode failed");
    }
  };

  const handle = async (request: IncomingMessage): Promise<Reply> => {
    const route = `${request.method ?? "GET"} ${new URL(request.url ?? "/", "http://localhost").pathname}`;

    if (route === "GET /health") return { status: 200, body: healthBody };
    if (route === "POST /decode/contract-state") return decode(request, (b) => decodeContractState(hexBytes(b, "`bytes`")));
    if (route === "POST /decode/transactions") return decode(request, (b) => decodeTransactions(hexList(b)));
    if (route !== "POST /respond") return failRedacted("not_found", `no route ${route}`, [config.fundingSeed]);

    return handleRespond(config, client, await readBody(request));
  };

  return createServer((request, response) => void handle(request)
      // Reached in normal operation: `readBody` rejects with `aborted` when a
      // client hangs up mid-body, so this catch includes disconnects.
      .catch((error: unknown) =>
        failRedacted("internal", error instanceof Error ? error.message : String(error), [config.fundingSeed], "unhandled"),
      )
      .then(({ status, body }) => response.writeHead(status, { "content-type": "application/json" }).end(body)));
}

export async function serve(config: Config, client: NodeClient): Promise<Server> {
  const server = buildServer(config, client);
  await new Promise<void>((resolve, reject) => server.once("error", reject).listen(config.port, config.bindHost, resolve));
  console.log(`midnight-publisher listening on ${config.bindHost}:${config.port}`);
  return server;
}
