import { afterEach, describe, expect, it, vi } from "vitest";

import { latestDustEventId, type ProbeSocket } from "../src/dust-probe.js";

// A graphql-transport-ws server for one socket, scripted by `answer`.
class FakeSocket implements ProbeSocket {
  onopen: ProbeSocket["onopen"] = null;
  onmessage: ProbeSocket["onmessage"] = null;
  onerror: ProbeSocket["onerror"] = null;
  onclose: ProbeSocket["onclose"] = null;
  readonly sent: Record<string, unknown>[] = [];
  closedWith: number | undefined;

  constructor(
    readonly url: string,
    readonly protocol: string,
    private readonly answer: (message: Record<string, unknown>, socket: FakeSocket) => void,
  ) {
    queueMicrotask(() => this.onopen?.({}));
  }

  send(data: string): void {
    const message = JSON.parse(data) as Record<string, unknown>;
    this.sent.push(message);
    this.answer(message, this);
  }

  reply(message: object): void {
    queueMicrotask(() => this.onmessage?.({ data: JSON.stringify(message) }));
  }

  close(code?: number): void {
    this.closedWith = code;
  }
}

function serving(answer: (message: Record<string, unknown>, socket: FakeSocket) => void) {
  const sockets: FakeSocket[] = [];
  const connect = (url: string, protocol: string) => {
    const socket = new FakeSocket(url, protocol, answer);
    sockets.push(socket);
    return socket;
  };
  return { sockets, connect };
}

// An indexer holding DUST events up to `maxId`.
const indexerAt = (maxId: unknown) =>
  serving((message, socket) => {
    if (message.type === "connection_init") socket.reply({ type: "connection_ack" });
    if (message.type === "subscribe") {
      socket.reply({
        id: message.id,
        type: "next",
        payload: { data: { dustLedgerEvents: { id: 5, maxId } } },
      });
    }
  });

afterEach(() => {
  vi.useRealTimers();
});

describe("latestDustEventId", () => {
  it("reads the indexer's highest DUST event id from the event the wallet applied last", async () => {
    const indexer = indexerAt(9);

    await expect(latestDustEventId("ws://indexer/ws", 5n, 3_000, indexer.connect)).resolves.toBe(
      9n,
    );

    const [socket] = indexer.sockets;
    expect(socket).toMatchObject({ url: "ws://indexer/ws", protocol: "graphql-transport-ws" });
    expect(socket!.sent[0]).toEqual({ type: "connection_init", payload: {} });
    expect(socket!.sent[1]).toMatchObject({
      id: "1",
      type: "subscribe",
      payload: { variables: { id: 5 } },
    });
    expect(String((socket!.sent[1]!.payload as { query: string }).query)).toMatch(
      /dustLedgerEvents\(id: \$id\) \{ id maxId \}/,
    );
    expect(socket!.closedWith).toBe(1000);
  });

  it("starts at the first event for a wallet that has applied none", async () => {
    const indexer = indexerAt(3);

    await latestDustEventId("ws://indexer/ws", 0n, 3_000, indexer.connect);

    expect(indexer.sockets[0]!.sent[1]).toMatchObject({ payload: { variables: { id: null } } });
  });

  it("answers the server's keep-alive ping while waiting", async () => {
    const indexer = serving((message, socket) => {
      if (message.type === "connection_init") {
        socket.reply({ type: "connection_ack" });
      }
      if (message.type === "subscribe") socket.reply({ type: "ping" });
      if (message.type === "pong") {
        socket.reply({
          id: "1",
          type: "next",
          payload: { data: { dustLedgerEvents: { maxId: 4 } } },
        });
      }
    });

    await expect(latestDustEventId("ws://indexer/ws", 4n, 3_000, indexer.connect)).resolves.toBe(
      4n,
    );
    expect(indexer.sockets[0]!.sent.map((message) => message.type)).toEqual([
      "connection_init",
      "subscribe",
      "pong",
    ]);
  });

  it("does not say when the indexer stays silent, errors, closes or sends nonsense", async () => {
    vi.useFakeTimers();
    const silent = serving(() => undefined);
    const pending = latestDustEventId("ws://indexer/ws", 5n, 3_000, silent.connect);
    await vi.advanceTimersByTimeAsync(3_000);
    await expect(pending).resolves.toBeUndefined();
    expect(silent.sockets[0]!.closedWith).toBe(1000);
    vi.useRealTimers();

    const errors = serving((message, socket) => {
      if (message.type === "connection_init") socket.reply({ type: "connection_ack" });
      if (message.type === "subscribe") socket.reply({ id: "1", type: "error", payload: [] });
    });
    await expect(
      latestDustEventId("ws://indexer/ws", 5n, 3_000, errors.connect),
    ).resolves.toBeUndefined();

    const closes = serving((_, socket) => queueMicrotask(() => socket.onclose?.({})));
    await expect(
      latestDustEventId("ws://indexer/ws", 5n, 3_000, closes.connect),
    ).resolves.toBeUndefined();

    for (const maxId of ["9", null, 2 ** 60]) {
      await expect(
        latestDustEventId("ws://indexer/ws", 5n, 3_000, indexerAt(maxId).connect),
      ).resolves.toBeUndefined();
    }

    const refused = () => {
      throw new Error("ECONNREFUSED");
    };
    await expect(latestDustEventId("ws://indexer/ws", 5n, 3_000, refused)).resolves.toBeUndefined();
  });
});
