/**
 * `POST /decode/transactions`: tagged ledger `Transaction` bytes in,
 * cross-contract-call provenance out. Pure codec; pulling the blobs out of a
 * block is the caller's job.
 *
 * Mechanism only: no address filtering, no request-id recompute, no proof
 * checks. A separate crate owns the security semantics.
 *
 * It deliberately does NOT recover the values a transaction wrote. A transcript
 * carries no insert record, and the chain answers that question directly: a
 * contract's state at block N minus the same read at N-1 IS the set of writes.
 * What a state diff cannot answer is WHICH transaction wrote, and that is what
 * this seam supplies, from the ledger's own `claimedContractCalls`.
 *
 * Two things the caller must get right when building the `bytes` array:
 * - `index` is the position in THAT ARRAY. The Rust fetcher numbers a block's
 *   transactions over a list that also holds one entry per
 *   `midnightSystem.SystemTransactionApplied` event; those carry no ledger
 *   transaction and cannot be sent here, so the caller keeps its own numbering.
 *   Counting only the decodable ones renumbers everything after a system
 *   transaction, silently, and only on chains that have them.
 * - The blob is the `midnight.send_mn_transaction` argument WITHOUT its SCALE
 *   compact length prefix. (`@polkadot/api` camelCases that method name;
 *   matching the runtime's snake_case spelling compiles, runs, matches nothing
 *   and returns an empty block with no error.)
 */

// Dual instance: `.../compact-runtime` re-exports onchain-runtime-v4, a
// different WASM instance whose objects fail `instanceof` here.
import { ContractCall, Transaction } from "@midnightntwrk/ledger-v9";
import type { AlignedValue, Binding, Proof, SignatureEnabled, Transcript } from "@midnightntwrk/ledger-v9";

import { toHex } from "./node.js";

/**
 * ledger-v9 prefixes every `Fr` with one constant tag byte, where Rust's
 * `Fr::as_le_bytes()` is the bare 32.
 *
 * Stripping it is mandatory and its absence is SILENT: nothing throws, the
 * response just carries 66-hex commitments where the consumer expects 64, and
 * the Step-3 equality still holds between two tagged values. The bug survives
 * every self-consistent test and shows up only as a byte diff against the Rust
 * seam. Pinned by `tests/block.test.ts`.
 */
const FR_TAG_BYTE = 0x73;

/** 1 tag byte + 32 little-endian bytes. */
const TAGGED_FR_HEX_LENGTH = 66;

type LedgerTransaction = Transaction<SignatureEnabled, Proof, Binding>;

/** One entry of a transcript's `claimedContractCalls`: a call it asserts it made. */
export interface ClaimedCall {
  readonly position: number;
  readonly address: string;
  readonly entry_point: string;
  /** Little-endian `Fr` bytes, tag stripped. */
  readonly commitment: string;
}

/**
 * The Step-3 link is `claimed[i].commitment === communication_commitment` of the
 * callee's own `DecodedCall` in the same transaction: that pair ties a caller to
 * the singleton call it made.
 */
export interface DecodedCall {
  readonly address: string;
  /** This call's own commitment (callee side). */
  readonly communication_commitment: string;
  /** Calls this call's transcripts claim to have made (caller side). */
  readonly claimed: readonly ClaimedCall[];
}

/**
 * Grouped per transaction because Step 3 asks whether ONE transaction called
 * both the singleton and the caller a notification names; a block-flat list
 * could not answer that when two transactions in a block both notify.
 */
export interface DecodedTransaction {
  /** Position in the request's `bytes` array. The only thing mapping a result back to its input. */
  readonly index: number;
  readonly calls: readonly DecodedCall[];
}

export interface DecodedTransactions {
  readonly transactions: readonly DecodedTransaction[];
  /**
   * Inputs deliberately survived rather than failed on, one reason each.
   * Non-empty means `transactions` is NOT known to cover every input.
   */
  readonly skipped: readonly string[];
}

/** Throws rather than emitting a value of the wrong width. */
function frBytes(hex: string): string {
  if (hex.length !== TAGGED_FR_HEX_LENGTH || Number.parseInt(hex.slice(0, 2), 16) !== FR_TAG_BYTE) {
    throw new Error(
      `unexpected Fr encoding: expected ${TAGGED_FR_HEX_LENGTH} hex chars tagged ` +
        `0x${FR_TAG_BYTE.toString(16)}, got ${hex}`,
    );
  }
  return hex.slice(2);
}

/** Throws rather than silently losing precision above 2^53. */
function positionNumber(position: bigint): number {
  if (position > Number.MAX_SAFE_INTEGER) {
    throw new Error(`claimed-call position ${position} exceeds the safe integer range`);
  }
  return Number(position);
}

/**
 * Position ascending, ties broken by commitment hex. Plain `<`/`>` on ASCII hex
 * is the byte order Rust's `String::cmp` gives; `localeCompare` is not.
 *
 * Exported because it IS the contract: no captured transaction claims from more
 * than one call, so no fixture can exercise this rule end to end.
 */
export function compareClaimedCalls(a: ClaimedCall, b: ClaimedCall): number {
  if (a.position !== b.position) return a.position - b.position;
  return a.commitment < b.commitment ? -1 : a.commitment > b.commitment ? 1 : 0;
}

/**
 * Sorted PER TRANSCRIPT, then concatenated guaranteed-first by the caller. That
 * is not the same as sorting the merged list: a global sort would interleave the
 * two transcripts' claims and change the response bytes.
 */
function claimedCalls(transcript: Transcript<AlignedValue>): ClaimedCall[] {
  return transcript.effects.claimedContractCalls
    .map(([position, address, entryPoint, commitment]) => ({
      position: positionNumber(position),
      address,
      entry_point: entryPoint,
      commitment: frBytes(toHex(commitment)),
    }))
    .sort(compareClaimedCalls);
}

export function callsFromTx(tx: LedgerTransaction): DecodedCall[] {
  return [...(tx.intents?.values() ?? [])]
    .flatMap((intent) => intent.actions)
    // `ContractAction` is also `ContractDeploy` and `MaintenanceUpdate`; neither
    // carries a transcript or a commitment.
    .filter((action) => action instanceof ContractCall)
    .map((action) => ({
      address: action.address,
      communication_commitment: frBytes(action.communicationCommitment),
      // Guaranteed then fallible: that concatenation IS the response order.
      claimed: [action.guaranteedTranscript, action.fallibleTranscript]
        .filter((t) => t !== undefined)
        .flatMap(claimedCalls),
    }));
}

/** The `send_mn_transaction` argument, already unwrapped from its extrinsic. */
export function decodeTransaction(bytes: Uint8Array): LedgerTransaction {
  return Transaction.deserialize("signature", "proof", "binding", bytes);
}

/**
 * One undecodable input costs that input, never the batch: a transaction version
 * this build does not know would otherwise hide every other call beside it.
 */
export function decodeTransactions(blobs: readonly Uint8Array[]): DecodedTransactions {
  const transactions: DecodedTransaction[] = [];
  const skipped: string[] = [];
  blobs.forEach((bytes, index) => {
    try {
      transactions.push({ index, calls: callsFromTx(decodeTransaction(bytes)) });
    } catch (error) {
      skipped.push(`tx[${index}]: ${error instanceof Error ? error.message : String(error)}`);
    }
  });
  return { transactions, skipped };
}
