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

import { redact, type Config } from "./config.js";
import { badRequest, fail, jsonObject, PublisherError, type ErrorCode, type Reply } from "./errors.js";
import { LEDGER_TAGS } from "./ledger.js";
import { fromHex, type NodeClient } from "./node.js";
import { decodeTransactions } from "./block.js";
import { handleRespond } from "./respond.js";
import { decodeContractState } from "./state.js";

type BodyLimit = { readonly bytes: number; readonly label: string };

/** A handful of 64-hex fields; past this is a bug or an attack. */
const RESPOND_LIMIT: BodyLimit = { bytes: 64 * 1024, label: "64 KiB" };

/** A transaction runs ~28 KB of hex, so this carries ~280 of them. */
const DECODE_LIMIT: BodyLimit = { bytes: 8 * 1024 * 1024, label: "8 MiB" };

/** Liveness plus the compatibility declaration. Deliberately not readiness. */
const HEALTH_BODY = JSON.stringify({ status: "ok", ledger: LEDGER_TAGS });

async function readBoundedBody(request: IncomingMessage, limit: BodyLimit): Promise<string | Reply> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request as AsyncIterable<Buffer>) {
    if ((size += chunk.length) > limit.bytes) return fail("payload_too_large", `body exceeds the ${limit.label} limit`);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function bytesMember(body: string): unknown {
  return jsonObject(body)["bytes"];
}

/**
 * Checked, not coerced: `Buffer.from(_, "hex")` truncates silently at the first
 * non-hex character, which would hand the ledger a short blob and blame the
 * caller's bytes for it.
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
  /** The envelope is the caller's, the bytes are the ledger's. */
  const decode = async (request: IncomingMessage, seam: (bytes: unknown) => unknown): Promise<Reply> => {
    const text = await readBoundedBody(request, DECODE_LIMIT);
    if (typeof text !== "string") return text;
    try {
      return { status: 200, body: JSON.stringify(seam(bytesMember(text))) };
    } catch (error) {
      const code = error instanceof PublisherError ? error.code : decodeFailureCode(error);
      const safe = redact(error instanceof Error ? error.message : String(error), [config.fundingSeed]);
      if (code !== "bad_request") console.error(`decode failed [${code}]: ${safe}`);
      return fail(code, safe);
    }
  };

  const handle = async (request: IncomingMessage): Promise<Reply> => {
    const route = `${request.method ?? "GET"} ${new URL(request.url ?? "/", "http://localhost").pathname}`;

    if (route === "GET /health") return { status: 200, body: HEALTH_BODY };
    if (route === "POST /decode/contract-state") return decode(request, (b) => decodeContractState(hexBytes(b, "`bytes`")));
    if (route === "POST /decode/transactions") return decode(request, (b) => decodeTransactions(hexList(b)));
    if (route !== "POST /respond") return fail("not_found", `no route ${route}`);

    const text = await readBoundedBody(request, RESPOND_LIMIT);
    return typeof text === "string" ? handleRespond(config, client, text) : text;
  };

  return createServer((request, response) => void handle(request)
      .catch((error: unknown) => {
        // Reached in normal operation: `readBoundedBody` rejects with `aborted`
        // when a client hangs up mid-body, so this log includes disconnects.
        const safe = redact(error instanceof Error ? error.message : String(error), [config.fundingSeed]);
        console.error(`unhandled: ${safe}`);
        return fail("internal", safe);
      })
      .then(({ status, body }) => response.writeHead(status, { "content-type": "application/json" }).end(body)));
}

export async function serve(config: Config, client: NodeClient): Promise<Server> {
  const server = buildServer(config, client);
  await new Promise<void>((resolve, reject) => server.once("error", reject).listen(config.port, config.bindHost, resolve));
  console.log(`midnight-publisher listening on ${config.bindHost}:${config.port}`);
  return server;
}
