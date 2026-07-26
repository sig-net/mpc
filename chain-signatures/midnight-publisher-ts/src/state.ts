/**
 * `POST /decode/contract-state`: tagged `contract-state[v8]` bytes in, tree out.
 * Pure codec.
 *
 * The schema deviates from `StateValue`'s own serialization on purpose: the
 * consumer needs field-aligned atoms exactly as the runtime stores them, so a
 * Compact struct's fields line up one to one.
 *
 * Failure is total, never partial: a blob walks to a complete tree or the
 * request fails loudly (version skew arrives as `ledger_mismatch`), so a diff
 * of two returned trees cannot miss a write.
 */

// Dual instance: everything here is ledger-v9's. The near-namesake
// `deserializeCompactContractState` yields the same class name from the OTHER
// wasm copy, so its values are foreign to these types.
import { deserializeContractState, toHex } from "@midnight-ntwrk/midnight-js-utils";
import type { StateValue } from "@midnightntwrk/ledger-v9";

/**
 * Atoms are trailing-zero-trimmed as stored, so the consumer re-pads and "" means
 * zero. Passed through untouched: re-padding here would change its bytes.
 */
export type StateNode =
  | { readonly kind: "null" }
  | { readonly kind: "cell"; readonly atoms: readonly string[] }
  | { readonly kind: "array"; readonly children: readonly StateNode[] }
  // One hex string per key atom: joined, a composite key's split point is
  // unrecoverable, since any atom can trim to nothing.
  | { readonly kind: "map"; readonly entries: readonly { readonly key: readonly string[]; readonly value: StateNode }[] };

/** Exported so tests walk a tree the way the seam does. */
export function walk(value: StateValue): StateNode {
  switch (value.type()) {
    case "null":
      return { kind: "null" };
    case "cell":
      return { kind: "cell", atoms: value.asCell().value.map(toHex) };
    // `type()` IS the discriminant, so the `undefined` these also allow is
    // unreachable: probed against every `StateValue` constructor, and `get`
    // cannot miss a key `keys()` just handed back.
    case "array":
      return { kind: "array", children: value.asArray()!.map(walk) };
    case "map": {
      const map = value.asMap()!;
      const entries = map.keys().map((key) => ({ key: key.value.map(toHex), value: walk(map.get(key)!) }));
      // Byte order, deliberately: `localeCompare` reorders under a non-C
      // collation. Join first, since `<` on arrays coerces via a comma-join.
      entries.sort((a, b) => {
        const x = a.key.join("");
        const y = b.key.join("");
        return x < y ? -1 : x > y ? 1 : 0;
      });
      return { kind: "map", entries };
    }
    // BoundedMerkleTree never occurs in the signet contracts' ledgers.
    default:
      throw new Error(`unsupported StateValue variant in signet contract state: ${value.type()}`);
  }
}

export function decodeContractState(raw: Uint8Array): StateNode {
  return walk(deserializeContractState(raw, { caller: "midnight-publisher:decodeContractState" }).data.state);
}
