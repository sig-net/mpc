// Two surfaces matter and only one appears in `rpc_methods`: the `midnight_*`
// namespace, and `MidnightRuntimeApi` through `state_call`, which is the only
// one carrying the zswap chain state and the live ledger parameters.

import { ApiPromise, WsProvider } from "@polkadot/api";

export type NodeClient = ApiPromise;

export type BlockHashHex = `0x${string}`;

// Stays `async` so a synchronous `new WsProvider(badUrl)` throw becomes a rejection.
export async function connect(nodeUrl: string): Promise<NodeClient> {
  return ApiPromise.create({ provider: new WsProvider(nodeUrl), noInitWarn: true });
}

type RuntimeApiNamespace = Record<string, (...args: readonly unknown[]) => Promise<unknown>>;

// Addresses MUST be `0x`-prefixed hex: `@polkadot/api` treats a `Uint8Array` as
// already SCALE-encoded and fails about a length rather than an encoding.
export async function runtimeApiBytes(
  client: NodeClient,
  blockHash: BlockHashHex,
  method: string,
  ...args: readonly unknown[]
): Promise<Uint8Array | undefined> {
  const fn = ((await client.at(blockHash)).call["midnightRuntimeApi"] as RuntimeApiNamespace | undefined)?.[method];
  if (fn === undefined) throw new Error(`node exposes no midnightRuntimeApi.${method}`);

  const result = (await fn(...args)) as { isOk: boolean; asOk: { toU8a(bare?: boolean): Uint8Array } };
  return result.isOk ? result.asOk.toU8a(true) : undefined;
}

// Truncates silently on anything but bare lowercase hex, which every caller has
// already rejected: `server.ts` for the decode seams, the schema for respond.
export function fromHex(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, "hex"));
}
