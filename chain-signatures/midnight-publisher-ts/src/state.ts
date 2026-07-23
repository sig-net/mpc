/**
 * `POST /decode/contract-state`: tagged `contract-state[v8]` bytes in, tree out.
 * Pure codec; the caller does the chain read.
 *
 * The schema deviates from `StateValue`'s own `serde::Serialize` on purpose, and
 * matches the Rust seam it replaces: the consumer needs field-aligned atoms as
 * the runtime stores them so a Compact struct's fields line up one to one.
 */

// Dual instance: `ContractState.data.state` is ledger-v9's own `StateValue`, so
// every type and accessor here must be ledger-v9's. `deserializeCompactContractState`
// is the near-namesake that yields onchain-runtime-v4's class instead, which this
// walker cannot traverse.
import { deserializeContractState } from "@midnight-ntwrk/midnight-js-utils";
import type { AlignedValue, StateValue } from "@midnightntwrk/ledger-v9";

import { toHex } from "./node.js";

export interface StateMapEntry {
  /** The key's atoms, hex, concatenated into one string. */
  readonly key: string;
  readonly value: StateNode;
}

/**
 * A node of the decoded tree. Atoms are trailing-zero-trimmed as stored, so the
 * consumer re-pads to each field width and an empty string means zero.
 */
export type StateNode =
  | { readonly kind: "null" }
  | { readonly kind: "cell"; readonly atoms: readonly string[] }
  | { readonly kind: "array"; readonly children: readonly StateNode[] }
  | { readonly kind: "map"; readonly entries: readonly StateMapEntry[] };

/** Narrows an `undefined` the return types allow but `type()` has ruled out. */
function present<T>(value: T | undefined, what: string): T {
  if (value === undefined) throw new Error(`ledger gave no ${what}`);
  return value;
}

/** Atoms are passed through untouched: re-padding would change the consumer's bytes. */
function valueAtoms(value: AlignedValue): string[] {
  return value.value.map(toHex);
}

/** Exported so the tests walk a tree exactly the way the seam does. */
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
        return { key: hex, value: walk(present(map.get(key), `entry for key ${hex}`)) };
      });
      // Plain `<`/`>` on ASCII hex is the byte order Rust's `String::cmp` gives.
      // `localeCompare` is not, and reorders under a non-C collation.
      entries.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
      return { kind: "map", entries };
    }
    // BoundedMerkleTree never occurs in the signet contracts' ledgers.
    default:
      throw new Error(`unsupported StateValue variant in signet contract state: ${kind}`);
  }
}

export function decodeContractState(raw: Uint8Array): StateNode {
  return walk(deserializeContractState(raw, { caller: "midnight-publisher:decodeContractState" }).data.state);
}
