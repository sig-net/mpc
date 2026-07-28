// Shared test scaffolding: the arrange step only.

import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";

import type { Config } from "../src/config.js";
import type { Reply } from "../src/errors.js";
import type { NodeClient } from "../src/node.js";
import { buildServer } from "../src/server.js";

export const FIXTURES = fileURLToPath(new URL("./fixtures/", import.meta.url));

// Endpoints that fail loudly if anything tries to use them. Spread it to vary a field.
export const TEST_CONFIG: Config = {
  port: 0,
  bindHost: "127.0.0.1",
  nodeUrl: "ws://127.0.0.1:1",
  proofServerUrl: "http://127.0.0.1:1",
  indexerUrl: "http://127.0.0.1:1",
  indexerWsUrl: "ws://127.0.0.1:1",
  managedDir: FIXTURES,
  networkId: "undeployed",
};

// ANY property access throws, which is what proves a path opens no connection.
export function forbiddenClient(what: string): NodeClient {
  return new Proxy({} as NodeClient, {
    get(_target, property) {
      throw new Error(`${what} (touched ${String(property)})`);
    },
  });
}

// A reply plus the header no `Reply` carries.
export interface Answer extends Reply {
  readonly contentType: string | null;
}

// The REAL server, held open so a suite can send more than one request to ONE instance.
export async function listening(config: Config, client: NodeClient, onFatal?: () => void) {
  const server = buildServer(config, client, onFatal);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as AddressInfo;
  return {
    async send(path: string, init?: RequestInit): Promise<Answer> {
      const response = await fetch(`http://127.0.0.1:${port}${path}`, init);
      return { status: response.status, body: await response.text(), contentType: response.headers.get("content-type") };
    },
    close(): void {
      server.closeAllConnections();
      server.close();
    },
  };
}

