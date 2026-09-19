// Whether an EVM endpoint is an anvil node, which decides what the setup may
// do with it: anvil takes the `anvil_*` dealing cheatcodes and traces the
// transactions it mines itself, a real chain behind a public RPC does neither.

import { jsonRpcRequest, parseJsonRpcReply } from "./json-rpc.ts";

/**
 * Whether the endpoint is anvil, read from `web3_clientVersion` (anvil
 * reports `anvil/v<version>`), which every node answers.
 *
 * @param rpcUrl - The JSON-RPC endpoint to ask.
 * @returns True when anvil answers, false for any other node or a non-JSON answer.
 * @throws {Error} When the endpoint does not answer at all.
 */
export async function isAnvil(rpcUrl: string): Promise<boolean> {
  const reply = parseJsonRpcReply(await jsonRpcRequest(rpcUrl, "web3_clientVersion", []));
  const version = reply?.result;
  return typeof version === "string" && version.toLowerCase().startsWith("anvil");
}
