// Which ledger this build speaks, published at `GET /health`. These are the
// ledger's own tags, so they move when the encoding moves.

import { PublisherError } from "./errors.js";

export const LEDGER_TAGS = {
  contractState: "midnight:contract-state[v8]",
  zswapChainState: "midnight:zswap-ledger-state[v5]",
  ledgerParameters: "midnight:ledger-parameters[v8]",
  transaction: "midnight:transaction[v12]",
} as const;

// Fires before the deserializer, where an untagged blob usually means a bad runtime-API argument.
export function assertLedgerTag(bytes: Uint8Array, tag: string, what: string): void {
  const head = Buffer.from(bytes.subarray(0, 96)).toString("latin1");
  if (head.includes(tag)) return;
  throw new PublisherError(
    "ledger_mismatch",
    `${what} is not a ${tag} blob (leading bytes: ${JSON.stringify(head.slice(0, 48))}). ` +
      `Either the chain moved past the ledger this build links, or the runtime-API argument ` +
      `encoding was wrong: addresses must be passed as 0x-prefixed hex strings, never as Uint8Array.`,
  );
}
