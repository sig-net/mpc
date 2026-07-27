// `POST /decode/transactions`: tagged ledger `Transaction` bytes in,
// cross-contract-call provenance out. Pure codec, mechanism only.
//
// Writes are recovered by diffing contract state across blocks, not from
// transcripts; this seam answers the one thing a diff cannot, which transaction
// made a given call. Presence of a call does not imply the fallible segment ran.

import { deserializeLedgerTransaction, toHex } from "@midnight-ntwrk/midnight-js-utils";
import { ContractCall } from "@midnightntwrk/ledger-v9";
import type { AlignedValue, FinalizedTransaction, Transcript } from "@midnightntwrk/ledger-v9";

// ledger-v9 tags every `Fr`; the wire carries the bare 32 LE bytes. Failing to
// strip it is SILENT: commitments come out 66 hex instead of 64.
const FR_TAG_HEX = "73";
const TAGGED_FR_HEX_LENGTH = 66;

export interface ClaimedCall {
  readonly position: number;
  readonly address: string;
  readonly entry_point: string;
  // Little-endian `Fr` bytes, tag stripped.
  readonly commitment: string;
}

// `claimed[i].commitment` matching a callee's own `communication_commitment` ties the two.
export interface DecodedCall {
  readonly address: string;
  readonly communication_commitment: string;
  readonly claimed: readonly ClaimedCall[];
}

export interface DecodedTransaction {
  // Position in the request's `transactions` array, which maps a result to its input.
  readonly index: number;
  readonly calls: readonly DecodedCall[];
}

export interface DecodedTransactions {
  readonly transactions: readonly DecodedTransaction[];
  // Always empty on a version-matched chain, so non-empty means the block is unprocessed.
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

// Plain `<`/`>` on ASCII hex is byte order; `localeCompare` is locale collation and is not.
export function compareClaimedCalls(a: ClaimedCall, b: ClaimedCall): number {
  if (a.position !== b.position) return a.position - b.position;
  return a.commitment < b.commitment ? -1 : a.commitment > b.commitment ? 1 : 0;
}

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

export function decodeTransaction(bytes: Uint8Array): FinalizedTransaction {
  return deserializeLedgerTransaction(bytes, { caller: "midnight-publisher:decodeTransaction" });
}

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
