/**
 * The Midnight node client, shared by every read seam.
 *
 * Two surfaces matter and only one of them appears in `rpc_methods`:
 * the `midnight_*` JSON-RPC namespace (five methods), and `MidnightRuntimeApi`
 * (ten), which is reached through `state_call` and is invisible to an
 * `rpc_methods` listing. The zswap chain state and the live ledger parameters
 * exist only on the second. Two separate investigations concluded "the node
 * cannot serve it" from the first and both were wrong.
 */

import { ApiPromise, WsProvider } from "@polkadot/api";

/** A connected node client plus the raw provider, which undecorated RPCs need. */
export interface NodeClient {
  readonly api: ApiPromise;
  /**
   * Kept explicitly: `@polkadot/api` 16 has no `api.rpc.provider`, and reaching
   * an undecorated RPC such as `midnight_contractState` requires the provider
   * you handed to `ApiPromise.create`. The obvious spelling fails at runtime,
   * not at compile time.
   */
  readonly provider: WsProvider;
  disconnect(): Promise<void>;
}

/**
 * Connect to the node.
 *
 * @param nodeUrl - Substrate ws endpoint.
 * @returns The connected client.
 */
export async function connect(nodeUrl: string): Promise<NodeClient> {
  const provider = new WsProvider(nodeUrl);
  const api = await ApiPromise.create({ provider, noInitWarn: true });
  return { api, provider, disconnect: () => api.disconnect() };
}

/** A block the seams anchor a read to. */
export interface Anchor {
  readonly height: number;
  /** Bare lowercase hex, no `0x`, matching this integration's address and atom convention. */
  readonly hash: string;
}

/** `0x`-prefixed 64-hex, the form every block-hash argument takes. */
export type BlockHashHex = `0x${string}`;

/**
 * True when `value` is a `0x`-prefixed 32-byte block hash.
 *
 * A type predicate rather than a cast at the call site, so the check and the
 * narrowing cannot drift apart. Both read seams validate this same shape and
 * reject it with their own message, so the shape lives here beside
 * {@link BlockHashHex} and only the message stays at the seam.
 *
 * @param value - The raw query-parameter text.
 * @returns Whether it is a well-formed block hash.
 */
export function isBlockHash(value: string): value is BlockHashHex {
  return value.startsWith("0x") && isHex(value.slice(2), 32);
}

/**
 * Resolve an anchor: the given block, or the finalized head when none is given.
 *
 * @param client - The node client.
 * @param at - Optional `0x`-prefixed block hash.
 * @returns The anchor's height and bare-hex hash, plus the `0x` form for further calls.
 */
export async function resolveAnchor(
  client: NodeClient,
  at: BlockHashHex | undefined,
): Promise<{ anchor: Anchor; blockHash: BlockHashHex }> {
  const blockHash = at ?? ((await client.api.rpc.chain.getFinalizedHead()).toHex() as BlockHashHex);
  const header = await client.api.rpc.chain.getHeader(blockHash);
  return { anchor: { height: header.number.toNumber(), hash: blockHash.slice(2) }, blockHash };
}

/** A runtime-API namespace as `@polkadot/api` decorates it: method name -> call. */
type RuntimeApiNamespace = Record<string, (...args: readonly unknown[]) => Promise<unknown>>;

/**
 * Call a `MidnightRuntimeApi` method returning `Result<Vec<u8>, LedgerApiError>`.
 *
 * Argument encoding is the trap here. The Rust signature is `Vec<u8>`, and
 * `@polkadot/api` treats a `Uint8Array` as ALREADY SCALE-encoded, compact-decoding
 * its head as a length: passing raw address bytes fails with
 * `createType(Bytes):: Bytes length 816158570 exceeds 10485760`, an error that
 * names a length rather than an encoding. Pass a `0x`-prefixed hex string.
 *
 * @param client - The node client.
 * @param blockHash - Block to pin the call to.
 * @param method - Runtime API method name, e.g. `getZswapChainState`.
 * @param args - Arguments, addresses as `0x`-prefixed hex strings.
 * @returns The decoded byte payload, or undefined when the runtime returned an error.
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

/**
 * One-shot undecorated JSON-RPC call. Used for `midnight_contractState`, which
 * `@polkadot/api` does not decorate.
 *
 * @param client - The node client.
 * @param method - JSON-RPC method name.
 * @param params - Positional parameters.
 * @returns The raw string result.
 */
export async function rpc(client: NodeClient, method: string, params: unknown[]): Promise<string> {
  return client.provider.send<string>(method, params);
}

/** Decode a `0x`-prefixed or bare hex string into bytes. */
export function fromHex(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex.replace(/^0x/, ""), "hex"));
}

/** Hex-encode bytes, bare lowercase, no `0x`. */
export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/** True when `value` is exactly `bytes` bytes of lowercase hex. */
export function isHex(value: string, bytes: number): boolean {
  return value.length === bytes * 2 && /^[0-9a-f]+$/.test(value);
}
