/**
 * `GET /block`: decode a finalized block into per-transaction cross-contract-call
 * provenance.
 *
 * Mechanism only: no contract-address filtering, no request-id recompute, no
 * proof checks. Every contract call of every transaction is reported with its
 * raw provenance; a separate crate owns the security semantics.
 *
 * WHAT THIS SEAM DELIBERATELY DOES NOT DO: recover the values a transaction
 * wrote. A transcript carries no insert record, so reading writes out of one
 * means either modelling the VM's stack effects by hand or replaying the program
 * against the contract's pre-state. Both are unnecessary, because the chain
 * answers that question directly: `midnight_contractState(addr, block)` minus
 * the same read at the parent block IS the set of writes that block made to that
 * contract, which is what `/state?at=` exists to serve.
 *
 * What a state diff CANNOT answer is which transaction performed a write, and
 * SGN2 Step 3 needs exactly that: the transaction that posted a notification
 * must also contain a contract call on the caller that notification names. That
 * is what this seam supplies, taken straight from the ledger's own
 * `Effects.claimedContractCalls` and each call's `communicationCommitment`.
 *
 * Pipeline (no GraphQL indexer anywhere on it):
 *   `chain_getBlock` + `System::Events`
 *     -> the block's transaction slots, in the Rust fetcher's order
 *     -> ledger `Transaction` bytes out of each `midnight.sendMnTransaction`
 *     -> per `ContractCall`, its two transcripts (guaranteed / fallible)
 *        -> `Transcript.effects.claimedContractCalls` (Step 3, caller side)
 *        -> `ContractCall.communicationCommitment`    (Step 3, callee side)
 */

// Dual-instance discipline: every ledger type on this path comes from the one
// entry point that owns it. `@midnight-ntwrk/midnight-js-protocol/ledger` is a
// bare `export *` of this package and is the same instance;
// `.../compact-runtime` re-exports `@midnight-ntwrk/compact-runtime`
// (onchain-runtime-v4) and is a DIFFERENT WASM instance whose objects fail
// `instanceof` here.
import { ContractCall, Transaction } from "@midnightntwrk/ledger-v9";
import type { AlignedValue, Binding, Proof, SignatureEnabled, Transcript } from "@midnightntwrk/ledger-v9";
import type { Vec } from "@polkadot/types";
import type { EventRecord } from "@polkadot/types/interfaces";

import type { Config } from "./config.js";
import { isBlockHash, toHex, type BlockHashHex, type NodeClient } from "./node.js";
import type { Reply } from "./server.js";

/**
 * ledger-v9 prefixes every `Fr` with one constant tag byte, so a commitment
 * arrives as 33 bytes where Rust's `Fr::as_le_bytes()` is the bare 32.
 *
 * This MUST be stripped. Left on, nothing throws and nothing warns: the response
 * simply carries 66-hex commitments where the consumer expects 64, and the
 * Step-3 equality `claimed[i].commitment == communicationCommitment` still holds
 * between two tagged values, so the bug survives every self-consistent test and
 * only shows up as a byte diff against the Rust seam. Pinned by
 * `tests/block.test.ts`.
 */
const FR_TAG_BYTE = 0x73;

/** Hex length of a tagged `Fr`: 1 tag byte + 32 little-endian bytes. */
const TAGGED_FR_HEX_LENGTH = 66;

/**
 * The extrinsic that carries a ledger `Transaction` blob.
 *
 * `@polkadot/api` camelCases the runtime's snake_case `send_mn_transaction`.
 * Matching the runtime's own spelling compiles, runs, matches nothing, and
 * returns an empty block with no error, so both halves of the name are pinned
 * here and asserted against a block that plainly contains one.
 */
const MIDNIGHT_TX_SECTION = "midnight";
const MIDNIGHT_TX_METHOD = "sendMnTransaction";

/** The event a system transaction is recovered from on a non-genesis block. */
const SYSTEM_TX_SECTION = "midnightSystem";
const SYSTEM_TX_EVENT = "SystemTransactionApplied";

/** The ledger transaction shape this chain produces: signature / proof / pedersen-schnorr binding. */
type LedgerTransaction = Transaction<SignatureEnabled, Proof, Binding>;

/**
 * One entry of a transcript's `claimedContractCalls` effects set: a call this
 * transcript asserts it made into another contract.
 */
export interface ClaimedCall {
  /** Position of the claimed call within the claiming transcript. */
  readonly position: number;
  /** Callee contract address, hex. */
  readonly address: string;
  /** Callee entry-point hash, hex. */
  readonly entry_point: string;
  /** Callee `communicationCommitment`, hex (little-endian `Fr` bytes, tag stripped). */
  readonly commitment: string;
}

/**
 * One contract call, carrying both sides of its cross-call provenance.
 *
 * The Step-3 link is `claimed[i].commitment === communication_commitment` of the
 * callee's own `BlockCall` in the same transaction: that pair is what ties a
 * caller to the singleton call it made.
 */
export interface BlockCall {
  /** The contract this call executes against, hex. */
  readonly address: string;
  /** This call's own commitment (callee side), hex little-endian `Fr`. */
  readonly communication_commitment: string;
  /** Calls this call's transcripts claim to have made (caller side). */
  readonly claimed: readonly ClaimedCall[];
}

/**
 * The contract calls of a single transaction.
 *
 * Grouped per transaction on purpose: Step 3 asks whether ONE transaction called
 * both the singleton and the caller the notification names, and a block-flat
 * list could not answer that without ambiguity when two transactions in the same
 * block both notify.
 */
export interface BlockTransaction {
  /** Position of this transaction in the block's transaction list. See {@link TransactionSlot}. */
  readonly index: number;
  readonly calls: readonly BlockCall[];
}

/** The `GET /block` response body, before serialization. */
export interface BlockResponse {
  readonly transactions: readonly BlockTransaction[];
  /**
   * Transactions this response deliberately survived rather than failed on, one
   * human-readable reason each. A block carries every transaction on the chain,
   * including shapes this build does not know, so one undecodable transaction
   * must never cost the caller the rest of the block. Non-empty means
   * `transactions` is NOT known to be complete for this block.
   */
  readonly skipped: readonly string[];
}

/**
 * One slot of a block's transaction list.
 *
 * System slots carry no ledger `Transaction` and are never decoded, but they
 * OCCUPY AN INDEX. `BlockTransaction.index` is the position in this list, which
 * is how the Rust implementation numbers transactions (its fetcher appends a
 * `RawTransaction::System` per `SystemTransactionApplied` event alongside the
 * `RawTransaction::Midnight` entries), so dropping them would silently renumber
 * every midnight transaction that follows one.
 */
export type TransactionSlot =
  | { readonly kind: "midnight"; readonly bytes: Uint8Array }
  | { readonly kind: "system" };

/**
 * Strip ledger-v9's one-byte `Fr` tag, yielding the 32 raw little-endian bytes
 * Rust's `Fr::as_le_bytes()` produces.
 *
 * @param hex - A tagged `Fr` rendered as bare hex.
 * @returns The untagged 64-hex little-endian value.
 * @throws If the tag or the length is not what this ledger build produces,
 *   rather than silently emitting a value of the wrong width.
 */
function frBytes(hex: string): string {
  if (hex.length !== TAGGED_FR_HEX_LENGTH || Number.parseInt(hex.slice(0, 2), 16) !== FR_TAG_BYTE) {
    throw new Error(
      `unexpected Fr encoding: expected ${TAGGED_FR_HEX_LENGTH} hex chars tagged ` +
        `0x${FR_TAG_BYTE.toString(16)}, got ${hex}`,
    );
  }
  return hex.slice(2);
}

/**
 * A claimed call's sequence number as a JSON number.
 *
 * @param position - The ledger's `u64` sequence number.
 * @returns The same value as a number.
 * @throws Rather than silently losing precision above 2^53.
 */
function positionNumber(position: bigint): number {
  if (position > Number.MAX_SAFE_INTEGER) {
    throw new Error(`claimed-call position ${position} exceeds the safe integer range`);
  }
  return Number(position);
}

/**
 * The response's pinned ordering for claimed calls: position ascending, ties
 * broken by commitment hex ascending.
 *
 * Plain `<`/`>` on ASCII hex is the byte-wise order Rust's `String::cmp`
 * produces; `localeCompare` is not, and would reorder under a non-C collation.
 *
 * Exported because it IS the contract. No captured transaction claims from more
 * than one call, so this rule cannot be exercised end-to-end by any fixture on
 * hand; pinning it directly is the only way it stays honest.
 *
 * @param a - Left entry.
 * @param b - Right entry.
 * @returns Negative, zero or positive per the `Array.prototype.sort` contract.
 */
export function compareClaimedCalls(a: ClaimedCall, b: ClaimedCall): number {
  if (a.position !== b.position) return a.position - b.position;
  return a.commitment < b.commitment ? -1 : a.commitment > b.commitment ? 1 : 0;
}

/**
 * The `claimedContractCalls` of one transcript, decoded and ordered.
 *
 * The ledger holds these in a set with no stable iteration order, so they are
 * sorted PER TRANSCRIPT and the two transcripts are then concatenated
 * guaranteed-first. That is not the same as sorting the merged list, and it is
 * what the Rust seam does; a global sort would interleave the two transcripts'
 * claims and change the response bytes for any call that claims from both.
 *
 * @param transcript - The transcript whose effects to read.
 * @returns The claimed calls, sorted by position then commitment.
 */
function claimedCalls(transcript: Transcript<AlignedValue>): ClaimedCall[] {
  return transcript.effects.claimedContractCalls
    .map(([position, address, entryPoint, commitment]) => ({
      // Rust field order: position, address, entry_point, commitment.
      position: positionNumber(position),
      address,
      entry_point: entryPoint,
      commitment: frBytes(toHex(commitment)),
    }))
    .sort(compareClaimedCalls);
}

/**
 * Every contract call of a decoded transaction, with its provenance.
 *
 * @param tx - The deserialized ledger transaction.
 * @returns One entry per contract call, across every intent segment.
 */
export function callsFromTx(tx: LedgerTransaction): BlockCall[] {
  return [...(tx.intents?.values() ?? [])]
    .flatMap((intent) => intent.actions)
    // `ContractAction` is also `ContractDeploy` and `MaintenanceUpdate`;
    // neither carries a transcript or a commitment.
    .filter((action) => action instanceof ContractCall)
    .map((action) => ({
      // Rust field order: address, communication_commitment, claimed.
      address: action.address,
      communication_commitment: frBytes(action.communicationCommitment),
      // Guaranteed first, then fallible: that concatenation IS the response order.
      claimed: [action.guaranteedTranscript, action.fallibleTranscript]
        .filter((t) => t !== undefined)
        .flatMap(claimedCalls),
    }));
}

/**
 * Deserialize tagged ledger `Transaction` bytes: the `midnight_tx` argument
 * already unwrapped from its `send_mn_transaction` extrinsic.
 *
 * @param bytes - The tagged transaction bytes.
 * @returns The deserialized transaction.
 */
export function decodeTransaction(bytes: Uint8Array): LedgerTransaction {
  return Transaction.deserialize("signature", "proof", "binding", bytes);
}

/**
 * Decode a block's transaction slots into the response body.
 *
 * One undecodable transaction costs that transaction, never the block: a
 * transaction version this build does not know yet would otherwise fail the
 * request and hide every other call beside it. Whatever is dropped is reported
 * in `skipped` so the loss is visible to the caller.
 *
 * @param slots - The block's transaction list, system slots included.
 * @returns The decoded transactions and the reasons any were dropped.
 */
export function decodeBlock(slots: readonly TransactionSlot[]): BlockResponse {
  const transactions: BlockTransaction[] = [];
  const skipped: string[] = [];
  slots.forEach((slot, index) => {
    if (slot.kind !== "midnight") return;
    try {
      // Rust field order: index, calls.
      transactions.push({ index, calls: callsFromTx(decodeTransaction(slot.bytes)) });
    } catch (error) {
      skipped.push(`tx[${index}]: ${error instanceof Error ? error.message : String(error)}`);
    }
  });
  // Rust field order: transactions, skipped.
  return { transactions, skipped };
}

/**
 * The block's transaction list, in the order the Rust fetcher builds it.
 *
 * Per extrinsic, in extrinsic order: a midnight slot when the call is
 * `midnight.sendMnTransaction`, then one system slot per
 * `midnightSystem.SystemTransactionApplied` event emitted while applying that
 * extrinsic. The timestamp inherent contributes no slot of its own.
 *
 * Genesis is deliberately not special-cased. The Rust fetcher reads system
 * transactions straight off the extrinsics there, but it also panics on genesis
 * for want of a timestamp inherent, so there is no behaviour to match.
 *
 * @param client - The node client.
 * @param blockHash - The block to read.
 * @returns The block's slots, in index order.
 */
export async function blockSlots(
  client: NodeClient,
  blockHash: BlockHashHex,
): Promise<TransactionSlot[]> {
  const signedBlock = await client.api.rpc.chain.getBlock(blockHash);
  const at = await client.api.at(blockHash);
  // Pallet and storage names are runtime lookups against whatever this chain
  // actually exposes, not compile-time facts, so the absence is handled rather
  // than asserted away.
  const events = await at.query.system?.events?.<Vec<EventRecord>>();
  if (events === undefined) throw new Error("node exposes no System::Events storage");

  const slots: TransactionSlot[] = [];
  signedBlock.block.extrinsics.forEach(({ method }, index) => {
    if (method.section === MIDNIGHT_TX_SECTION && method.method === MIDNIGHT_TX_METHOD) {
      const arg = method.args[0];
      if (arg === undefined) {
        throw new Error(`${MIDNIGHT_TX_SECTION}.${MIDNIGHT_TX_METHOD} carried no transaction blob`);
      }
      // `toU8a(true)` drops the SCALE compact length prefix, leaving exactly the
      // tagged ledger `Transaction` bytes.
      slots.push({ kind: "midnight", bytes: arg.toU8a(true) });
    }
    for (const { phase, event } of events) {
      const applied = phase.isApplyExtrinsic && phase.asApplyExtrinsic.toNumber() === index;
      if (applied && event.section === SYSTEM_TX_SECTION && event.method === SYSTEM_TX_EVENT) {
        slots.push({ kind: "system" });
      }
    }
  });
  return slots;
}

/**
 * `GET /block?hash=0x<64hex>` -> 200 `{transactions,skipped}` / 400 bad hash /
 * 502 fetch or decode failure (raised by the caller's guard).
 *
 * The hash is validated before a single network call: a malformed request must
 * cost a round trip to the node, not answer one.
 *
 * @param _config - Unused by this read seam; present because every handler takes
 *   the same `(config, client, url)` shape. Underscored so `noUnusedParameters`
 *   stays on for the handlers that do read it.
 * @param client - Connected node client.
 * @param url - The request URL, for its query string.
 * @returns The status and already-serialized body.
 */
export async function handleBlock(_config: Config, client: NodeClient, url: URL): Promise<Reply> {
  const hash = url.searchParams.get("hash");
  if (hash === null) return { code: 400, body: "missing `hash` query param" };
  if (!isBlockHash(hash)) {
    return { code: 400, body: "hash must be `0x` followed by 64 lowercase hex" };
  }

  return { code: 200, body: JSON.stringify(decodeBlock(await blockSlots(client, hash))) };
}
