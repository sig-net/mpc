// The wallet SDK reports an indexer socket drop only as `[object CloseEvent]`: graphql-ws
// hands it the close event and the SDK stringifies it. graphql-ws builds its sockets from
// the global `WebSocket` when the SDK passes none, so a subclass installed before any
// wallet starts sees every one of them.

// The SDK's subscription operations, by the sub-wallet that opens each.
const SUB_WALLETS: Readonly<Record<string, string>> = {
  ZswapEvents: "shielded",
  ShieldedTransactions: "shielded",
  UnshieldedTransactions: "unshielded",
  DustLedgerEvents: "dust",
};

function subWalletOf(data: unknown): string | undefined {
  if (typeof data !== "string" || !data.includes('"subscribe"')) return undefined;
  try {
    const message = JSON.parse(data) as { type?: unknown; payload?: { query?: unknown } };
    if (message.type !== "subscribe" || typeof message.payload?.query !== "string") {
      return undefined;
    }
    const operation = /^\s*subscription\s+(\w+)/.exec(message.payload.query)?.[1];
    return operation === undefined ? undefined : SUB_WALLETS[operation];
  } catch {
    return undefined;
  }
}

/**
 * Logs one line per closed SDK indexer socket with its close code, reason and `wasClean`,
 * and the sub-wallet it served. Sockets that never carried one of the SDK's subscriptions
 * are not logged.
 */
export function logIndexerSocketCloses(log: (line: string) => void = console.error): void {
  const Native = globalThis.WebSocket;
  if (Native === undefined) return;
  class LoggedWebSocket extends Native {
    #subWallet: string | undefined;

    constructor(...args: ConstructorParameters<typeof WebSocket>) {
      super(...args);
      const [url] = args;
      const openedMs = Date.now();
      const host = new URL(String(url)).host;
      this.addEventListener(
        "close",
        (event) => {
          if (this.#subWallet === undefined) return;
          log(
            `indexer socket closed sub_wallet=${this.#subWallet} code=${event.code} ` +
              `reason=${JSON.stringify(event.reason)} was_clean=${event.wasClean} ` +
              `open_for=${((Date.now() - openedMs) / 1_000).toFixed(1)}s host=${host}`,
          );
        },
        { once: true },
      );
    }

    override send(data: Parameters<WebSocket["send"]>[0]): void {
      this.#subWallet ??= subWalletOf(data);
      super.send(data);
    }
  }
  globalThis.WebSocket = LoggedWebSocket;
}
