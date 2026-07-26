/**
 * `POST /decode/transactions`: tagged ledger `Transaction` bytes in,
 * cross-contract-call provenance out. Pure codec, mechanism only — no address
 * filtering, no request-id recompute, no proof checks.
 *
 * Writes are recovered by diffing contract state across blocks, not from
 * transcripts. This seam answers the one thing a diff cannot: which transaction
 * made a given call.
 *
 * Loss is only ever whole-transaction, never silent: a decoded transaction
 * reports every call and claim in its BODY (presence does not imply the
 * fallible segment executed; the caller-ledger read is the execution check),
 * and an undecodable one lands in `skipped`. On a version-matched chain skips
 * never happen (the node deserialized everything it included), so a skip is
 * ledger skew or a caller-side extraction bug.
 */

import { deserializeLedgerTransaction, toHex } from "@midnight-ntwrk/midnight-js-utils";
import { ContractCall } from "@midnightntwrk/ledger-v9";
import type { AlignedValue, FinalizedTransaction, Transcript } from "@midnightntwrk/ledger-v9";

/**
 * ledger-v9 tags every `Fr`; the wire carries the bare 32 LE bytes. Failing
 * to strip it is SILENT — commitments come out 66 hex instead of 64 and every
 * self-consistent test still passes.
 */
const FR_TAG_HEX = "73";

/** 1 tag byte + 32 little-endian bytes. */
const TAGGED_FR_HEX_LENGTH = 66;

/** A call a transcript asserts it made. */
export interface ClaimedCall {
  readonly position: number;
  readonly address: string;
  readonly entry_point: string;
  /** Little-endian `Fr` bytes, tag stripped. */
  readonly commitment: string;
}

/**
 * `claimed[i].commitment === communication_commitment` of the callee's own entry
 * in the same transaction is what ties a caller to the call it made.
 */
export interface DecodedCall {
  readonly address: string;
  /** This call's own commitment (callee side). */
  readonly communication_commitment: string;
  /** Calls this call's transcripts claim to have made (caller side). */
  readonly claimed: readonly ClaimedCall[];
}

/** Grouped per transaction: a block-flat list could not say which one made both calls. */
export interface DecodedTransaction {
  /** Position in the request's `transactions` array, which is what maps a result to its input. */
  readonly index: number;
  readonly calls: readonly DecodedCall[];
}

export interface DecodedTransactions {
  readonly transactions: readonly DecodedTransaction[];
  /**
   * Inputs survived rather than failed on, `tx[<index>]: <reason>` each.
   * Non-empty is never routine (see header): treat the block as unprocessed,
   * not partially indexed.
   */
  readonly skipped: readonly string[];
}

function frBytes(hex: string): string {
  if (hex.length !== TAGGED_FR_HEX_LENGTH || !hex.startsWith(FR_TAG_HEX)) {
    throw new Error(`unexpected Fr encoding: expected ${TAGGED_FR_HEX_LENGTH} hex chars tagged 0x${FR_TAG_HEX}, got ${hex}`);
  }
  return hex.slice(2);
}

function positionNumber(position: bigint): number {
  if (position > Number.MAX_SAFE_INTEGER) throw new Error(`claimed-call position ${position} exceeds the safe integer range`);
  return Number(position);
}

/**
 * Plain `<`/`>` on ASCII hex is byte order; `localeCompare` is locale
 * collation and is not. Exported because no fixture can exercise it.
 */
export function compareClaimedCalls(a: ClaimedCall, b: ClaimedCall): number {
  if (a.position !== b.position) return a.position - b.position;
  return a.commitment < b.commitment ? -1 : a.commitment > b.commitment ? 1 : 0;
}

/** Sorted per transcript. A global sort would interleave the two and change the bytes. */
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

export function callsFromTx(tx: FinalizedTransaction): DecodedCall[] {
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
export function decodeTransaction(bytes: Uint8Array): FinalizedTransaction {
  return deserializeLedgerTransaction(bytes, { caller: "midnight-publisher:decodeTransaction" });
}

/** One undecodable input costs that input, never the batch. */
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
