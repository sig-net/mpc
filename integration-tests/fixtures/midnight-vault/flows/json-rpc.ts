// One raw JSON-RPC call over fetch, for the setup probes that need the
// node's verbatim answer (its HTTP status, its error code and message) and
// must never retry: an ethers provider keeps retrying network detection
// against an endpoint that does not answer, where a probe wants to fail.

/** The error half of a JSON-RPC reply. */
export interface JsonRpcError {
  readonly code: number;
  readonly message: string;
}

/** A JSON-RPC reply, either half present. */
export interface JsonRpcReply {
  readonly result?: unknown;
  readonly error?: JsonRpcError;
}

/** What the endpoint answered: the HTTP status and the raw body. */
export interface JsonRpcAnswer {
  readonly status: number;
  readonly text: string;
}

/**
 * POST one JSON-RPC request and return the raw answer, without parsing it.
 *
 * @param rpcUrl - The JSON-RPC endpoint.
 * @param method - The method to call.
 * @param params - Its positional parameters.
 * @returns The HTTP status and body.
 * @throws {Error} Whatever `fetch` throws when the endpoint does not answer.
 */
export async function jsonRpcRequest(
  rpcUrl: string,
  method: string,
  params: readonly unknown[],
): Promise<JsonRpcAnswer> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return { status: response.status, text: await response.text() };
}

/**
 * Parse a JSON-RPC answer's body.
 *
 * @param answer - The raw answer.
 * @returns The parsed reply, or undefined when the body is not JSON.
 */
export function parseJsonRpcReply(answer: JsonRpcAnswer): JsonRpcReply | undefined {
  try {
    return JSON.parse(answer.text) as JsonRpcReply;
  } catch {
    return undefined;
  }
}
