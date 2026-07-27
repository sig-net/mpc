// The schema deviates from `StateValue`'s own serialization on purpose: the
// consumer needs field-aligned atoms exactly as the runtime stores them, so a
// Compact struct's fields line up one to one. A cell's alignment crosses with
// its atoms because a trimmed atom no longer says how wide it was declared, and
// the consumer decodes by that declared width.

// Dual instance: the near-namesake `deserializeCompactContractState` yields the
// same class name from the OTHER wasm copy, whose values are foreign to these types.
import { deserializeContractState, toHex } from "@midnight-ntwrk/midnight-js-utils";
import type { StateValue } from "@midnightntwrk/ledger-v9";

// The ledger's own `Alignment`, verbatim: a flat width list could express neither
// `compress` and `field`, which have no byte length, nor a nested `option`.
export type AlignmentAtom = { readonly tag: "compress" } | { readonly tag: "field" } | { readonly tag: "bytes"; readonly length: number };
export type AlignmentSegment =
  | { readonly tag: "option"; readonly value: readonly AlignmentSegment[][] }
  | { readonly tag: "atom"; readonly value: AlignmentAtom };

// Atoms are trailing-zero-trimmed as stored: the consumer re-pads, and "" means zero.
export type StateNode =
  | { readonly kind: "null" }
  // One alignment segment per atom, in atom order.
  | { readonly kind: "cell"; readonly atoms: readonly string[]; readonly alignment: readonly AlignmentSegment[] }
  | { readonly kind: "array"; readonly children: readonly StateNode[] }
  // One hex string per key atom: joined, a composite key's split point is lost.
  | { readonly kind: "map"; readonly entries: readonly { readonly key: readonly string[]; readonly value: StateNode }[] };

export function walk(value: StateValue): StateNode {
  switch (value.type()) {
    case "null":
      return { kind: "null" };
    case "cell": {
      const cell = value.asCell();
      return { kind: "cell", atoms: cell.value.map(toHex), alignment: cell.alignment };
    }
    // `type()` IS the discriminant, so the `undefined` these also allow is unreachable.
    case "array":
      return { kind: "array", children: value.asArray()!.map(walk) };
    case "map": {
      const map = value.asMap()!;
      const entries = map.keys().map((key) => ({ key: key.value.map(toHex), value: walk(map.get(key)!) }));
      // Byte order, deliberately: `localeCompare` reorders under a non-C collation.
      entries.sort((a, b) => {
        const x = a.key.join("");
        const y = b.key.join("");
        return x < y ? -1 : x > y ? 1 : 0;
      });
      return { kind: "map", entries };
    }
    default:
      throw new Error(`unsupported StateValue variant in signet contract state: ${value.type()}`);
  }
}

export function decodeContractState(raw: Uint8Array): StateNode {
  return walk(deserializeContractState(raw, { caller: "midnight-publisher:decodeContractState" }).data.state);
}
