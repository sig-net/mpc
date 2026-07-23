/**
 * The localhost HTTP seam. Routes, status codes and response bodies are
 * byte-compatible with the Rust implementation this replaces: `chain-midnight`
 * talks to this service over HTTP and must not be able to tell which
 * implementation is behind it.
 *
 * Seams:
 *   GET  /health                        -> 200 "ok"
 *   GET  /state?address=<64hex>[&at=]   -> 200 {anchor,tree} | 400 | 502
 *   GET  /block?hash=0x<64hex>          -> 200 {transactions,skipped} | 400 | 502
 *   POST /respond                       -> 200 {"status":"ok"} | 400 | 502
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { redact, secrets, type Config } from "./config.js";
import type { NodeClient } from "./node.js";
import { handleBlock } from "./block.js";
import { handleRespond } from "./respond.js";
import { handleState } from "./state.js";

/** A handler's verdict: an HTTP status and a body, already serialized. */
export interface Reply {
  readonly code: number;
  readonly body: string;
}

/**
 * Upper bound on a `POST /respond` body. The payload is a handful of 64-hex
 * fields; anything beyond this is a bug or an attack, not a real request.
 */
const MAX_RESPOND_BODY_BYTES = 64 * 1024;

async function readBoundedBody(request: IncomingMessage): Promise<string | undefined> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request as AsyncIterable<Buffer>) {
    if ((size += chunk.length) > MAX_RESPOND_BODY_BYTES) return undefined;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function send(response: ServerResponse, { code, body }: Reply): void {
  response.writeHead(code, { "content-type": code === 200 ? "application/json" : "text/plain" });
  response.end(body);
}

/**
 * Build the HTTP server. Does not listen; see {@link serve}.
 *
 * @param config - Validated configuration.
 * @param client - Connected node client, shared by the read seams.
 * @returns The server.
 */
export function buildServer(config: Config, client: NodeClient): Server {
  const hidden = secrets(config);

  /** Any handler failure becomes a 502 with its message redacted at the source. */
  const guard = async (run: () => Promise<Reply>): Promise<Reply> => {
    try {
      return await run();
    } catch (error) {
      const safe = redact(error instanceof Error ? error.message : String(error), hidden);
      console.error(`handler failed: ${safe}`);
      return { code: 502, body: safe };
    }
  };

  /** Resolve a request to its reply. Every read seam takes the same `(config, client, url)`. */
  const handle = async (request: IncomingMessage): Promise<Reply> => {
    const url = new URL(request.url ?? "/", "http://localhost");
    const route = `${request.method ?? "GET"} ${url.pathname}`;

    if (route === "GET /health") return { code: 200, body: "ok" };
    if (route === "GET /state") return guard(() => handleState(config, client, url));
    if (route === "GET /block") return guard(() => handleBlock(config, client, url));
    if (route !== "POST /respond") return { code: 404, body: "not found" };

    const body = await readBoundedBody(request);
    if (body === undefined) return { code: 400, body: "body exceeds the 64 KiB limit" };
    return guard(() => handleRespond(config, client, body));
  };

  return createServer((request, response) => {
    void handle(request).then((reply) => send(response, reply));
  });
}

/**
 * Bind and serve until the process exits.
 *
 * @param config - Validated configuration.
 * @param client - Connected node client.
 * @returns The listening server.
 */
export async function serve(config: Config, client: NodeClient): Promise<Server> {
  const server = buildServer(config, client);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.port, config.bindHost, resolve);
  });
  console.log(`midnight-publisher listening on ${config.bindHost}:${config.port}`);
  return server;
}
