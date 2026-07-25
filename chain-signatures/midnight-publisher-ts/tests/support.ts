/**
 * Shared test scaffolding: the arrange step only. What each suite asserts, and
 * the fixtures it names, stay in the suite.
 */

import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";

import type { Config } from "../src/config.js";
import type { Reply } from "../src/errors.js";
import type { NodeClient } from "../src/node.js";
import { buildServer } from "../src/server.js";

export const FIXTURES = fileURLToPath(new URL("./fixtures/", import.meta.url));

export function fixtureBytes(name: string): Uint8Array {
  return Uint8Array.from(readFileSync(`${FIXTURES}${name}`));
}

export function goldenText(name: string): string {
  return readFileSync(`${FIXTURES}${name}`, "utf8");
}

/** Endpoints that would fail loudly if anything tried to use them. Spread it to vary a field. */
export const TEST_CONFIG: Config = {
  port: 0,
  bindHost: "127.0.0.1",
  nodeUrl: "ws://127.0.0.1:1",
  proofServerUrl: "http://127.0.0.1:1",
  indexerUrl: "http://127.0.0.1:1",
  indexerWsUrl: "ws://127.0.0.1:1",
  managedDir: FIXTURES,
  fundingSeed: "deadbeef".repeat(8),
  networkId: "undeployed",
};

/**
 * A node client that must never be reached: ANY property access throws `what`.
 * This is what proves a path opens no connection, rather than merely not
 * needing one.
 */
export function forbiddenClient(what: string): NodeClient {
  return new Proxy({} as NodeClient, {
    get(_target, property) {
      throw new Error(`${what} (touched ${String(property)})`);
    },
  });
}

/**
 * Round-trip a body through the REAL HTTP server, on an ephemeral port.
 *
 * Not a direct handler call: the envelope (method, path, JSON, hex) is as much
 * of the contract as the decoded tree is, and the caller on the other side is a
 * separate process.
 */
export async function request(path: string, init?: RequestInit): Promise<Reply> {
  const server = buildServer(TEST_CONFIG, forbiddenClient("a decode seam touched the node client"));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  try {
    const { port } = server.address() as AddressInfo;
    const response = await fetch(`http://127.0.0.1:${port}${path}`, init);
    return { status: response.status, body: await response.text() };
  } finally {
    server.closeAllConnections();
    server.close();
  }
}

/** {@link request}, as a `POST` carrying a body. */
export function post(path: string, body: string): Promise<Reply> {
  return request(path, { method: "POST", body });
}

/** {@link request}, as a bare `GET`. */
export function get(path: string): Promise<Reply> {
  return request(path);
}
