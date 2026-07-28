// The localhost HTTP seam.
//
// GET  /health                  -> {status, networkId, ledger}
// POST /respond                 -> {status, tx_id, block_hash}

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { type Config } from "./config.js";
import { fail, replyTo, type Reply } from "./errors.js";
import { LEDGER_TAGS } from "./ledger.js";
import { type NodeClient } from "./node.js";
import { handleRespond } from "./respond.js";

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request as AsyncIterable<Buffer>) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

// `onFatal` runs only after a `fatal` reply is flushed: the caller must learn its post may still land.
export function buildServer(config: Config, client: NodeClient, onFatal?: () => void): Server {
  // Deliberately liveness, not readiness.
  const healthBody = JSON.stringify({ status: "ok", networkId: config.networkId, ledger: LEDGER_TAGS });

  const handle = async (request: IncomingMessage): Promise<Reply> => {
    const route = `${request.method ?? "GET"} ${new URL(request.url ?? "/", "http://localhost").pathname}`;

    switch (route) {
      case "GET /health":
        return { status: 200, body: healthBody };
      case "POST /respond":
        return handleRespond(config, client, await readBody(request));
      default:
        return fail("not_found", `no route ${route}`);
    }
  };

  const answer = async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    // Reached in normal operation: a client that hangs up mid-body rejects the
    // body read, so this catch covers disconnects as well as handler faults.
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
