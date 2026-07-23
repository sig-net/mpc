/**
 * The node client, used by `POST /respond` alone. The decode seams are pure
 * codecs over bytes their caller already holds and never reach it.
 *
 * Two surfaces matter and only one appears in `rpc_methods`: the `midnight_*`
 * JSON-RPC namespace, and `MidnightRuntimeApi`, which is reached through
 * `state_call` and is invisible to an `rpc_methods` listing. The zswap chain
 * state and the live ledger parameters exist only on the second. Two separate
 * investigations concluded "the node cannot serve it" from the first.
 */

import { ApiPromise, WsProvider } from "@polkadot/api";

export interface NodeClient {
  readonly api: ApiPromise;
  disconnect(): Promise<void>;
}

/** `0x`-prefixed 64-hex, the form every block-hash argument takes. */
export type BlockHashHex = `0x${string}`;

export async function connect(nodeUrl: string): Promise<NodeClient> {
  const api = await ApiPromise.create({ provider: new WsProvider(nodeUrl), noInitWarn: true });
  return { api, disconnect: () => api.disconnect() };
}

/** Finalized, not best: a call built against an orphaned block is built against state that never existed. */
export async function finalizedHead(client: NodeClient): Promise<BlockHashHex> {
  return (await client.api.rpc.chain.getFinalizedHead()).toHex() as BlockHashHex;
}

/** A runtime-API namespace as `@polkadot/api` decorates it: method name -> call. */
type RuntimeApiNamespace = Record<string, (...args: readonly unknown[]) => Promise<unknown>>;

/**
 * Call a `MidnightRuntimeApi` method returning `Result<Vec<u8>, LedgerApiError>`.
 * Returns undefined when the runtime answered with an error.
 *
 * Addresses MUST be `0x`-prefixed hex strings. `@polkadot/api` treats a
 * `Uint8Array` as already SCALE-encoded and compact-decodes its head as a
 * length, failing with `Bytes length 816158570 exceeds 10485760` — an error that
 * names a length rather than an encoding.
 */
export async function runtimeApiBytes(
  client: NodeClient,
  blockHash: BlockHashHex,
  method: string,
  ...args: readonly unknown[]
): Promise<Uint8Array | undefined> {
  const at = await client.api.at(blockHash);
  const fn = (at.call["midnightRuntimeApi"] as RuntimeApiNamespace | undefined)?.[method];
  if (fn === undefined) throw new Error(`node exposes no midnightRuntimeApi.${method}`);

  const result = (await fn(...args)) as { isOk: boolean; asOk: { toU8a(bare?: boolean): Uint8Array } };
  return result.isOk ? result.asOk.toU8a(true) : undefined;
}

/** Assumes already-checked hex; this truncates silently. Wire input goes through `server.ts`. */
export function fromHex(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex.replace(/^0x/, ""), "hex"));
}

/** Bare lowercase, no `0x`. */
export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function isHex(value: string, bytes: number): boolean {
  return value.length === bytes * 2 && /^[0-9a-f]+$/.test(value);
}
