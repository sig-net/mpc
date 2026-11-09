// The indexer's view of the DUST ledger, read over a socket of its own: the wallet SDK's
// sockets have no pong timeout, so a half-open one leaves the wallet reporting "synced"
// on a DUST tree the node no longer accepts proofs against.

// Named apart from the SDK's `DustLedgerEvents`, so it is never taken for the wallet's own.
const PROBE_QUERY =
  "subscription PublisherDustProbe($id: Int) { dustLedgerEvents(id: $id) { id maxId } }";

/** The subset of the WHATWG WebSocket this probe drives, so tests can stand one in. */
export interface ProbeSocket {
  onopen: ((event: unknown) => void) | null;
  onmessage: ((event: { readonly data: unknown }) => void) | null;
  onerror: ((event: unknown) => void) | null;
  onclose: ((event: unknown) => void) | null;
  send(data: string): void;
  close(code?: number): void;
}

export type ProbeSocketFactory = (url: string, protocol: string) => ProbeSocket;

const nativeSocket: ProbeSocketFactory = (url, protocol) =>
  new WebSocket(url, protocol) as unknown as ProbeSocket;

/**
 * The highest DUST ledger event id the indexer holds, from the `maxId` it sends with the
 * event at `fromId` (the subscription is inclusive, and a wallet's applied index names an
 * event that exists). Undefined when the indexer did not say within `timeoutMs`; never throws.
 */
export function latestDustEventId(
  indexerWsUrl: string,
  fromId: bigint,
  timeoutMs: number,
  connect: ProbeSocketFactory = nativeSocket,
): Promise<bigint | undefined> {
  return new Promise((resolve) => {
    let socket: ProbeSocket | undefined;
    let done = false;
    const finish = (latest: bigint | undefined): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(latest);
      try {
        socket?.close(1000);
      } catch {
        // Already closed.
      }
    };
    const timer = setTimeout(() => finish(undefined), timeoutMs);
    const send = (message: object): void => {
      try {
        socket?.send(JSON.stringify(message));
      } catch {
        finish(undefined);
      }
    };
    try {
      socket = connect(indexerWsUrl, "graphql-transport-ws");
    } catch {
      finish(undefined);
      return;
    }
    socket.onopen = () => send({ type: "connection_init", payload: {} });
    socket.onmessage = (event) => {
      let message: { type?: unknown; id?: unknown; payload?: unknown };
      try {
        message = JSON.parse(String(event.data)) as typeof message;
      } catch {
        finish(undefined);
        return;
      }
      switch (message.type) {
        case "connection_ack":
          send({
            id: "1",
            type: "subscribe",
            payload: {
              query: PROBE_QUERY,
              // A fresh wallet has applied nothing: start at the first event.
              variables: { id: fromId > 0n ? Number(fromId) : null },
            },
          });
          return;
        case "ping":
          send({ type: "pong" });
          return;
        case "next": {
          const maxId = (
            message.payload as { data?: { dustLedgerEvents?: { maxId?: unknown } } } | undefined
          )?.data?.dustLedgerEvents?.maxId;
          finish(
            typeof maxId === "number" && Number.isSafeInteger(maxId) ? BigInt(maxId) : undefined,
          );
          return;
        }
        case "pong":
          return;
        default:
          finish(undefined);
      }
    };
    socket.onerror = () => finish(undefined);
    socket.onclose = () => finish(undefined);
  });
}
