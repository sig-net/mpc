/**
 * The localhost HTTP seam.
 *
 *   GET  /health                  -> {status, ledger}
 *   POST /decode/contract-state   -> the state tree
 *   POST /decode/transactions     -> {transactions, skipped}
 *   POST /respond                 -> {"status":"ok"}
 *
 * The decode seams are pure codecs and open no connection; they are POST rather
 * than GET only because a serialized transaction runs ~14 KB and a batch of them
 * does not fit a query string.
 *
 * Every failure is `{"code","message"}` as `application/json`; see `errors.ts`.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { redact, secrets, type Config } from "./config.js";
import { badRequest, errorBody, PublisherError, statusFor, type ErrorCode } from "./errors.js";
import { LEDGER_TAGS } from "./ledger.js";
import { fromHex, type NodeClient } from "./node.js";
import { decodeTransactions } from "./block.js";
import { handleRespond } from "./respond.js";
import { decodeContractState } from "./state.js";

export interface Reply {
  readonly status: number;
  readonly body: string;
}

interface BodyLimit {
  readonly bytes: number;
  readonly label: string;
}

/** A handful of 64-hex fields; past this is a bug or an attack. */
const RESPOND_LIMIT: BodyLimit = { bytes: 64 * 1024, label: "64 KiB" };

/**
 * A transaction measured 14,405 bytes, so ~28 KB of hex: 8 MiB carries ~280 of
 * them, far more than a block holds, while staying under the 10 MiB ceiling
 * `@polkadot/api` puts on a single SCALE `Bytes` value.
 */
const DECODE_LIMIT: BodyLimit = { bytes: 8 * 1024 * 1024, label: "8 MiB" };

/**
 * Liveness, and the compatibility declaration the caller asserts at startup.
 * Readiness would have to reach the node, the indexer and the proof server, and
 * a caller that reads "a dependency is down" as "the publisher is down" restarts
 * the wrong process.
 */
const HEALTH_BODY = JSON.stringify({ status: "ok", ledger: LEDGER_TAGS });

async function readBoundedBody(request: IncomingMessage, limit: BodyLimit): Promise<string | undefined> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request as AsyncIterable<Buffer>) {
    if ((size += chunk.length) > limit.bytes) return undefined;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function bytesMember(body: string): unknown {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (error) {
    throw badRequest(`invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw badRequest("invalid JSON: expected a JSON object");
  }
  return (parsed as Record<string, unknown>)["bytes"];
}

/**
 * Bare or `0x`-prefixed, either case: the sender is another service and
 * rejecting a spelling that decodes unambiguously buys only an interop trap.
 *
 * CHECKED, not coerced. `Buffer.from(_, "hex")` stops at the first non-hex
 * character and truncates an odd-length string, so an unchecked decode hands the
 * ledger a silently short blob and reports its failure against bytes the caller
 * never sent.
 */
function hexBytes(value: unknown, what: string): Uint8Array {
  if (typeof value !== "string") throw badRequest(`${what} must be a hex string`);
  const hex = value.startsWith("0x") ? value.slice(2) : value;
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw badRequest(`${what} must be a whole number of bytes of hex, optionally \`0x\`-prefixed`);
  }
  return fromHex(hex);
}

/**
 * A malformed hex string fails the whole request rather than becoming a
 * `skipped` entry: answering 200 with everything skipped would hide a caller's
 * typo behind a success. Only bytes the LEDGER refuses survive per item.
 */
function hexList(value: unknown): Uint8Array[] {
  if (!Array.isArray(value)) throw badRequest("`bytes` must be an array of hex strings");
  return value.map((item: unknown, index) => hexBytes(item, `\`bytes[${index}]\``));
}

function send(response: ServerResponse, { status, body }: Reply): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(body);
}

/** Built from the code, so status and body cannot disagree. */
function fail(code: ErrorCode, message: string): Reply {
  return { status: statusFor(code), body: errorBody(code, message) };
}

export function buildServer(config: Config, client: NodeClient): Server {
  const hidden = secrets(config);

  const body = async (request: IncomingMessage, limit: BodyLimit): Promise<string | Reply> => {
    const text = await readBoundedBody(request, limit);
    return text ?? fail("payload_too_large", `body exceeds the ${limit.label} limit`);
  };

  /**
   * The envelope is the caller's (`bad_request`); the bytes are the ledger's
   * (`decode_failed`), which includes a version skew, indistinguishable here
   * from a corrupt blob. `GET /health` publishes the tags that tell them apart.
   */
  const decode = async (request: IncomingMessage, seam: (bytes: unknown) => string): Promise<Reply> => {
    const text = await body(request, DECODE_LIMIT);
    if (typeof text !== "string") return text;
    try {
      return { status: 200, body: seam(bytesMember(text)) };
    } catch (error) {
      const code = error instanceof PublisherError ? error.code : "decode_failed";
      const safe = redact(error instanceof Error ? error.message : String(error), hidden);
      if (code !== "bad_request") console.error(`decode failed [${code}]: ${safe}`);
      return fail(code, safe);
    }
  };

  const handle = async (request: IncomingMessage): Promise<Reply> => {
    const url = new URL(request.url ?? "/", "http://localhost");
    const route = `${request.method ?? "GET"} ${url.pathname}`;

    if (route === "GET /health") return { status: 200, body: HEALTH_BODY };
    if (route === "POST /decode/contract-state") {
      return decode(request, (bytes) => JSON.stringify(decodeContractState(hexBytes(bytes, "`bytes`"))));
    }
    if (route === "POST /decode/transactions") {
      return decode(request, (bytes) => JSON.stringify(decodeTransactions(hexList(bytes))));
    }
    if (route !== "POST /respond") return fail("not_found", `no route ${route}`);

    const text = await body(request, RESPOND_LIMIT);
    return typeof text === "string" ? handleRespond(config, client, text) : text;
  };

  return createServer((request, response) => {
    void handle(request)
      .catch((error: unknown) => {
        // Reached in normal operation, not only on a bug: `readBoundedBody`'s
        // `for await` rejects with `aborted` whenever a client hangs up
        // mid-body, and nothing upstream catches that. Answer anyway, since a
        // hung socket is worse than a 500 (the response goes nowhere if the peer
        // is already gone). The log line below will therefore include client
        // disconnects; treat `aborted` as noise rather than as a seam failure.
        const safe = redact(error instanceof Error ? error.message : String(error), hidden);
        console.error(`unhandled: ${safe}`);
        return fail("internal", safe);
      })
      .then((reply) => send(response, reply));
  });
}

export async function serve(config: Config, client: NodeClient): Promise<Server> {
  const server = buildServer(config, client);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.port, config.bindHost, resolve);
  });
  console.log(`midnight-publisher listening on ${config.bindHost}:${config.port}`);
  return server;
}
