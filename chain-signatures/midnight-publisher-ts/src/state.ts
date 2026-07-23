/**
 * `GET /state`: an anchored contract-state read.
 *
 * `chain_getFinalizedHead` (or an explicit `at`) -> `chain_getHeader` ->
 * `midnight_contractState`, then walk the ledger `StateValue` tree into the
 * pinned `{anchor,tree}` schema. No GraphQL indexer is on this path.
 *
 * The schema is a DELIBERATE deviation from `StateValue`'s own upstream
 * `serde::Serialize`, carried over unchanged from the Rust implementation this
 * replaces (`midnight-publisher/src/state.rs`): the consumer needs the
 * field-aligned atoms exactly as the runtime stores them (each
 * trailing-zero-trimmed, re-padded to the declared width on the far side) so a
 * Compact struct's fields line up one-to-one. Upstream's representation answers
 * a different question.
 *
 * `at` is what lets a caller ask "what did block N write to this contract?":
 * read the contract at N and at N's parent and diff the two trees. That is the
 * whole basis of write discovery; see `block.ts` for why it replaces trying to
 * recover writes out of a transaction's transcript.
 */

// Dual-instance discipline: `ContractState.data.state` is ledger-v9's OWN
// `StateValue`, so `ContractState`, `StateValue` and `AlignedValue` must all
// come from ledger-v9 and be walked by ledger-v9's own accessors.
// `@midnight-ntwrk/midnight-js-protocol/ledger` is a bare `export *` of this
// package, so that spelling is the same instance and equally safe;
// `@midnight-ntwrk/midnight-js-protocol/compact-runtime` is NOT — it re-exports
// `@midnight-ntwrk/compact-runtime` (onchain-runtime-v4), a second WASM instance
// whose objects this walker cannot traverse. Import each type from the entry
// point the interface it belongs to names.
//
// The same fork runs through the deserializers: `deserializeContractState` wraps
// the LEDGER `ContractState.deserialize` and is the one to use here, while its
// near-namesake `deserializeCompactContractState` wraps the compact-runtime
// class and would hand this walker an untraversable object.
import { deserializeContractState } from "@midnight-ntwrk/midnight-js-utils";
import type { AlignedValue, StateValue } from "@midnightntwrk/ledger-v9";

import type { Config } from "./config.js";
import { fromHex, isBlockHash, isHex, resolveAnchor, rpc, toHex } from "./node.js";
import type { Anchor, BlockHashHex, NodeClient } from "./node.js";
import type { Reply } from "./server.js";

/** One `key`/`value` pair of a decoded `StateValue::Map`. */
export interface StateMapEntry {
  /** The key's field-aligned atoms, hex-encoded and concatenated into one string. */
  readonly key: string;
  readonly value: StateNode;
}

/**
 * One node of the decoded contract-state tree, tagged on `kind`. Mirrors the
 * Rust `state::Node` serde shape exactly:
 * - `{"kind":"null"}`
 * - `{"kind":"cell","atoms":["<hex>",...]}` — one atom per field-aligned value
 *   segment, trailing-zero-trimmed exactly as the runtime stores it (the
 *   consumer re-pads to each field width; an empty string means zero/default).
 * - `{"kind":"array","children":[<StateNode>,...]}`
 * - `{"kind":"map","entries":[{"key":"<hex>","value":<StateNode>},...]}` —
 *   entries sorted by key hex.
 */
export type StateNode =
  | { readonly kind: "null" }
  | { readonly kind: "cell"; readonly atoms: readonly string[] }
  | { readonly kind: "array"; readonly children: readonly StateNode[] }
  | { readonly kind: "map"; readonly entries: readonly StateMapEntry[] };

/** The `GET /state` response body, before serialization. The block a read was anchored to, then its tree. */
export interface StateResponse {
  readonly anchor: Anchor;
  readonly tree: StateNode;
}

/**
 * Narrow away an `undefined` the ledger's return types allow but `type()` has
 * already ruled out. Throws rather than letting the walk emit a node of the
 * wrong shape from a value it could not read.
 *
 * @param value - The ledger's optional return.
 * @param what - What was being read, for the error text.
 * @returns The value, guaranteed present.
 */
function present<T>(value: T | undefined, what: string): T {
  if (value === undefined) throw new Error(`ledger gave no ${what}`);
  return value;
}

/**
 * The field-aligned atoms of a cell or map key, hex-encoded.
 *
 * Each atom is stored trailing-zero-trimmed by the runtime and is passed through
 * untouched: re-padding here would change the bytes the consumer parses.
 *
 * @param value - The aligned value to render.
 * @returns One hex string per value segment, in declaration order.
 */
function valueAtoms(value: AlignedValue): string[] {
  return value.value.map(toHex);
}

/**
 * Walk a ledger `StateValue` into the pinned schema.
 *
 * Exported so `/block`'s state-diff tests and any future consumer decode a tree
 * exactly the way the seam does, rather than reimplementing the traversal.
 *
 * @param value - The state value to walk.
 * @returns The decoded node.
 * @throws On a `StateValue` variant the signet contracts' ledgers never carry.
 */
export function walk(value: StateValue): StateNode {
  const kind = value.type();
  switch (kind) {
    case "null":
      return { kind: "null" };
    case "cell":
      return { kind: "cell", atoms: valueAtoms(value.asCell()) };
    case "array":
      return { kind: "array", children: present(value.asArray(), kind).map(walk) };
    case "map": {
      const map = present(value.asMap(), kind);
      const entries = map.keys().map((key) => {
        const hex = valueAtoms(key).join("");
        // Written in the schema's field order: `key` then `value`.
        return { key: hex, value: walk(present(map.get(key), `entry for key ${hex}`)) };
      });
      // Schema pins map entries sorted by key hex. Plain `<`/`>` on ASCII hex is
      // the byte-wise order Rust's `String::cmp` produces; `localeCompare` is
      // not, and would reorder under a non-C collation.
      entries.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
      return { kind: "map", entries };
    }
    // BoundedMerkleTree never occurs in the signet contracts' ledgers.
    default:
      throw new Error(`unsupported StateValue variant in signet contract state: ${kind}`);
  }
}

/**
 * Deserialize tagged `contract-state[v8]` bytes and walk the tree.
 *
 * Accepts both the node's hex-decoded `midnight_contractState` blob and a
 * captured state fixture: they are the same bytes.
 *
 * @param raw - The tagged contract-state bytes.
 * @returns The decoded tree.
 * @throws {DeserializationError} Naming this call site, and classifying a
 *   version mismatch between these bytes and this build's ledger.
 */
export function decodeContractState(raw: Uint8Array): StateNode {
  const ctx = { caller: "midnight-publisher:decodeContractState" };
  return walk(deserializeContractState(raw, ctx).data.state);
}

/**
 * Substring of the node's catch-all "I could not answer" error. Not a
 * pruning-specific signal on its own: both failure modes below come back as
 * `-32602` with no `data` field, so the CODE cannot discriminate and the text
 * is the only thing that can.
 *
 *   pruned / unreachable state : "Unable to get requested contract state"
 *   contract did not exist yet : "Contract not present at the requested address"
 */
const UNABLE = "unable to get requested contract state";

/**
 * True when a failed anchored state read looks like pruning rather than a
 * missing contract. Callers should raise this loudly rather than folding it into
 * a generic fetch failure: one means "this contract did not exist yet", the
 * other means "this node has lost the ability to answer".
 *
 * @param message - The error text the node returned.
 * @returns Whether the message is the catch-all that pruning produces.
 */
function looksLikePruning(message: string): boolean {
  return message.toLowerCase().includes(UNABLE);
}

/**
 * Read a contract's state at a block and decode it.
 *
 * @param client - The node client.
 * @param address - Contract address, bare 64 lowercase hex.
 * @param at - Block to anchor to, `0x`-prefixed; the finalized head when absent.
 * @returns The anchor and the decoded tree.
 * @throws Loudly and distinctly when the failure is this node having pruned the
 *   state, rather than the contract being absent. See {@link looksLikePruning}.
 */
export async function fetchState(
  client: NodeClient,
  address: string,
  at: BlockHashHex | undefined,
): Promise<StateResponse> {
  const { anchor, blockHash } = await resolveAnchor(client, at);

  let blob: string;
  try {
    // Address = bare 64-hex, no `0x`; `at` = the `0x`-prefixed block hash.
    blob = await rpc(client, "midnight_contractState", [address, blockHash]);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // The header at this block was just fetched successfully, so the block is
    // known and reachable. A contract-state read that still fails with the
    // node's catch-all is therefore the pruning signature, NOT "this contract
    // did not exist yet" — those two share the -32602 code and differ only in
    // their text, so folding them together would report a misconfigured node as
    // a missing contract and send the operator looking in the wrong place.
    if (looksLikePruning(message)) {
      throw new Error(
        `this node has PRUNED contract state at height ${anchor.height} (block ` +
          `0x${anchor.hash}). The block itself is still served, so this is not a missing ` +
          `contract: state-diff discovery needs an archive node, started with ` +
          `'--state-pruning archive --blocks-pruning archive'. The mode can only be set when ` +
          `the database is first created, so an already-pruned database must be resynced. ` +
          `Node said: ${message}`,
      );
    }
    throw error;
  }

  return {
    // JSON key order is load-bearing: `chain-midnight` byte-compares this body
    // against the Rust implementation's, so the literals below are written in
    // the Rust struct's field order (`anchor` then `tree`; `height` then `hash`)
    // and must not be reordered.
    anchor: { height: anchor.height, hash: anchor.hash },
    tree: decodeContractState(fromHex(blob)),
  };
}

/**
 * `GET /state?address=<64hex>[&at=0x<64hex>]` -> 200 `{anchor,tree}` / 400 bad
 * address or `at` / 502 fetch or decode failure (raised by the caller's guard).
 *
 * Everything is validated before a single network call: a malformed request must
 * cost a round trip to the node, not answer one.
 *
 * @param _config - Unused by this read seam; present because every handler takes
 *   the same `(config, client, url)` shape. Underscored so `noUnusedParameters`
 *   stays on for the handlers that do read it.
 * @param client - Connected node client.
 * @param url - The request URL, for its query string.
 * @returns The status and already-serialized body.
 */
export async function handleState(_config: Config, client: NodeClient, url: URL): Promise<Reply> {
  const address = url.searchParams.get("address");
  if (address === null) return { code: 400, body: "missing `address` query param" };
  if (!isHex(address, 32)) return { code: 400, body: "address must be 64 lowercase hex" };

  const rawAt = url.searchParams.get("at");
  if (rawAt !== null && !isBlockHash(rawAt)) {
    return { code: 400, body: "at must be `0x` followed by 64 lowercase hex" };
  }

  return { code: 200, body: JSON.stringify(await fetchState(client, address, rawAt ?? undefined)) };
}
