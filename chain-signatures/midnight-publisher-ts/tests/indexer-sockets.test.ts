import { afterEach, describe, expect, it, vi } from "vitest";

import { logIndexerSocketCloses } from "../src/indexer-sockets.js";

// Stands in for the platform WebSocket: records sends, closes when told to.
class NativeSocket extends EventTarget {
  readonly sent: unknown[] = [];

  constructor(
    readonly url: string,
    readonly protocols?: string,
  ) {
    super();
  }

  send(data: unknown): void {
    this.sent.push(data);
  }

  drop(code: number, reason: string, wasClean: boolean): void {
    this.dispatchEvent(Object.assign(new Event("close"), { code, reason, wasClean }));
  }
}

const subscribe = (query: string) =>
  JSON.stringify({ id: "1", type: "subscribe", payload: { query, variables: { id: 4 } } });

function install() {
  vi.stubGlobal("WebSocket", NativeSocket);
  const lines: string[] = [];
  logIndexerSocketCloses((line) => lines.push(line));
  const open = (url = "ws://indexer.example:8088/api/v3/graphql/ws") =>
    new globalThis.WebSocket(url, "graphql-transport-ws") as unknown as NativeSocket;
  return { lines, open };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("logIndexerSocketCloses", () => {
  it("logs a closed SDK socket once, with its code, reason, wasClean and sub-wallet", async () => {
    const { lines, open } = install();
    const socket = open();
    socket.send(JSON.stringify({ type: "connection_init" }));
    socket.send(
      subscribe("subscription DustLedgerEvents($id: Int) {\n  dustLedgerEvents(id: $id) {"),
    );

    // Later frames on the same socket keep its sub-wallet.
    socket.send(JSON.stringify({ type: "pong" }));
    socket.send(JSON.stringify({ id: "1", type: "complete" }));
    socket.drop(1006, "", false);
    socket.drop(1006, "", false);

    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(
      /^indexer socket closed sub_wallet=dust code=1006 reason="" was_clean=false open_for=\d+\.\ds host=indexer\.example:8088$/,
    );
    // Passed through untouched.
    expect(socket.sent).toHaveLength(4);
    expect(socket.protocols).toBe("graphql-transport-ws");
  });

  it("names each sub-wallet by the subscription its socket carries", async () => {
    const { lines, open } = install();
    for (const [operation, reason] of [
      ["ZswapEvents", "shielded going away"],
      ["ShieldedTransactions", "shielded again"],
      ["UnshieldedTransactions", "unshielded"],
    ]) {
      const socket = open();
      socket.send(subscribe(`subscription ${operation}($id: Int) { x }`));
      socket.drop(1001, reason!, true);
    }

    expect(lines.map((line) => /sub_wallet=(\w+)/.exec(line)?.[1])).toEqual([
      "shielded",
      "shielded",
      "unshielded",
    ]);
    expect(lines[0]).toContain('code=1001 reason="shielded going away" was_clean=true');
  });

  it("leaves sockets alone that never carried an SDK subscription", async () => {
    const { lines, open } = install();
    const probe = open();
    probe.send(subscribe("subscription PublisherDustProbe($id: Int) { x }"));
    probe.drop(1000, "", true);
    const node = open("ws://node.example:9944");
    node.send(JSON.stringify({ id: 1, jsonrpc: "2.0", method: "chain_getHeader" }));
    node.drop(1006, "", false);
    const malformed = open();
    malformed.send('{"type":"subscribe", not json');
    malformed.drop(1006, "", false);

    expect(lines).toEqual([]);
  });
});
