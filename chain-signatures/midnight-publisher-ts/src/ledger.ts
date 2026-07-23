/**
 * Which ledger this build speaks.
 *
 * This package's entire compatibility surface is one question: does the ledger
 * linked in here still understand the chain the caller is reading? Left
 * implicit, a skew surfaces as a deserialization failure on perfectly good
 * bytes, which reads as "the publisher is broken". So the tags are published at
 * `GET /health` for the caller to assert at startup, and the three chain reads
 * on the write path check theirs before deserializing.
 *
 * These are the ledger's own tags, stamped into the leading bytes of everything
 * it serializes, so they move exactly when the encoding moves.
 */

import { PublisherError } from "./errors.js";

export const LEDGER_TAGS = {
  contractState: "midnight:contract-state[v8]",
  zswapChainState: "midnight:zswap-ledger-state[v5]",
  ledgerParameters: "midnight:ledger-parameters[v8]",
  transaction: "midnight:transaction[v12]",
} as const;

const TAG_WINDOW_BYTES = 64;

/**
 * Complements the `deserialize*` wrappers rather than duplicating them: they
 * classify what the ledger sees once parsing, this fires first and can name a
 * cause they cannot. An untagged blob usually means the runtime-API argument
 * encoding was wrong (see `runtimeApiBytes`), not that the deserializer broke.
 */
export function assertLedgerTag(bytes: Uint8Array, tag: string, what: string): void {
  const head = Buffer.from(bytes.subarray(0, TAG_WINDOW_BYTES)).toString("latin1");
  if (head.includes(tag)) return;
  throw new PublisherError(
    "ledger_mismatch",
    `${what} is not a ${tag} blob (leading bytes: ${JSON.stringify(head.slice(0, 48))}). ` +
      `Either the chain moved past the ledger this build links, or the runtime-API argument ` +
      `encoding was wrong: addresses must be passed as 0x-prefixed hex strings, never as Uint8Array.`,
  );
}
