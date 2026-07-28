// The half that spends: take the finished Intent the caller built, wrap it into a
// transaction, prove it, pay for it, post it.
//
// MECHANISM, NEVER AUTHORITY. The signature inside the intent was computed by the MPC
// threshold, and the call was decided by the caller against chain state it read and
// pinned. Nothing here chooses what to sign or who may write. The worst a bug here can
// do is drop a post or pay for one twice.

import { Intent, Transaction, type UnprovenIntent, type UnprovenTransaction } from "@midnightntwrk/ledger-v9";

import { SUBMIT_VAR_NAMES, type Config } from "./config.js";
import { describeFailure, PublisherError, type ErrorCode } from "./errors.js";
import { proveTransaction, type UnboundTransaction } from "./prover.js";
import { openFundingWallet, type FundingWallet, type Landed } from "./wallet.js";

// The ledger this build links. The Rust half writes these same bytes with its own
// ledger crate, so the tag is where a version split between the two halves surfaces.
const INTENT_TAG = "midnight:intent[v9]";
const INTENT_TAG_FAMILY = "midnight:intent[v";

// Long enough to read a tag that sits in the first few bytes, short enough to quote back.
const TAG_WINDOW = 64;

/**
 * The intent the caller built, read back with the ledger's own tagged reader.
 *
 * The markers are the instance tags, not classes, and they are the same three the
 * builder serialized under: a signature-enabled, pre-proof, pre-binding intent.
 */
export function decodeIntent(bytes: Uint8Array): UnprovenIntent {
  const head = Buffer.from(bytes.subarray(0, TAG_WINDOW)).toString("latin1");
  if (!head.includes(INTENT_TAG)) {
    // A different version of the right tag is the two halves of the seam disagreeing
    // about the ledger, which no request can fix; anything else is a malformed field.
    throw head.includes(INTENT_TAG_FAMILY)
      ? new PublisherError(
          "ledger_mismatch",
          `\`intent\` is not a ${INTENT_TAG} blob (leading bytes: ${JSON.stringify(head.slice(0, 32))}); ` +
            `the caller serialized it with a different ledger than this build links`,
        )
      : new PublisherError("bad_request", `invalid request: \`intent\` is not a ${INTENT_TAG} blob`);
  }

  try {
    return Intent.deserialize("signature", "pre-proof", "pre-binding", bytes);
  } catch (cause) {
    throw new PublisherError("bad_request", `invalid request: \`intent\` did not deserialize`, { cause });
  }
}

/** The two edges that need an endpoint, so priming one seam primes everything paid for. */
export interface Publisher {
  /** The proof server, carrying the managed dir's key material for the contract call. */
  readonly proveTx: (tx: UnprovenTransaction) => Promise<UnboundTransaction>;
  readonly wallet: FundingWallet;
}

// Every dependency here waits forever by default: a dead indexer never finishes wallet
// sync, the node client queues across reconnects, and the submission service waits for
// finality. Unbounded, any of them holds the busy gate silently and answers nobody.
export const SUBMIT_TIMEOUT = { ms: 6 * 60 * 1000 };

// `Promise.race` handles the loser, so the abandoned attempt's own late failure surfaces nowhere.
export async function withDeadline<T>(work: Promise<T>, ms: number, onTimeout: () => Error): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => void (timer = setTimeout(() => reject(onTimeout()), ms))),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

let publisherPromise: Promise<Publisher> | undefined;

async function buildPublisher(config: Config): Promise<Publisher> {
  const endpoints = config.endpoints;
  if (endpoints === undefined) {
    throw new PublisherError(
      "wallet_unsynced",
      `this deployment builds intents only and has no funding wallet; set ${SUBMIT_VAR_NAMES.join(", ")} to give it one`,
    );
  }
  return {
    proveTx: (tx) => proveTransaction(config.managedDir, endpoints.proofServerUrl, tx),
    wallet: await openFundingWallet(config.networkId, endpoints),
  };
}

// Memoized even while PENDING, so a hung indexer costs one wallet facade, not one per retry.
function publisher(config: Config): Promise<Publisher> {
  publisherPromise ??= buildPublisher(config).catch((error: unknown) => {
    publisherPromise = undefined;
    throw error;
  });
  return publisherPromise;
}

/** The test seam: stand in for everything that would need an endpoint. */
export function primePublisher(ready: Promise<Publisher>): void {
  publisherPromise = ready;
}

export async function closePublisher(): Promise<void> {
  const pending = publisherPromise;
  publisherPromise = undefined;
  inFlightId = undefined;
  if (pending === undefined) return;
  await pending.then((ready) => ready.wallet.close()).catch(() => undefined);
}

type Refinement = readonly [pattern: string, code: ErrorCode];

// Either spelling means back off, not that the request was wrong.
const DUST_SHORTFALL: readonly Refinement[] = [
  ["Wallet.InsufficientFunds", "wallet_unfunded"],
  ["could not balance dust", "wallet_unfunded"],
];

// Best-effort: the submission service flattens node errors, so this surfaces only in the cause chain.
const LOST_THE_RACE: readonly Refinement[] = [["ReadMismatch", "state_conflict"]];

// The refinements are the ONLY place this process matches on dependency error text.
async function step<T>(code: ErrorCode, run: () => Promise<T>, refine: readonly Refinement[] = []): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof PublisherError) throw error;
    const described = describeFailure(error);
    // Matched against a WIDER haystack than the answered message: Effect hides the real
    // cause on a Symbol that only `String` renders.
    const sharpened = refine.find(([pattern]) => `${described}\n${String(error)}`.includes(pattern))?.[1];
    throw new PublisherError(sharpened ?? code, described, { cause: error });
  }
}

async function post(config: Config, intent: UnprovenIntent): Promise<Landed> {
  const ready = await step("wallet_unsynced", () => publisher(config));
  // `fromParts`, not `addCalls`: the intent arrives already partitioned, with its
  // transcripts split and its communication commitment sampled, so there is nothing
  // left to place and no ledger parameters left to price it against. No Zswap offer
  // either, because a respond moves no coins; the wallet adds the fee inputs next.
  const proven = await step("prove_failed", () =>
    ready.proveTx(Transaction.fromParts(config.networkId, undefined, undefined, intent)),
  );
  const recipe = await step("balance_failed", () => ready.wallet.balanceTx(proven), DUST_SHORTFALL);
  const finalized = await step("prove_failed", () => ready.wallet.finalizeTx(recipe), DUST_SHORTFALL);
  return step("submit_rejected", () => ready.wallet.submitTx(finalized), LOST_THE_RACE);
}

let inFlightId: number | undefined;

// Nothing in the chain below is cancellable, so a submit past its deadline keeps
// spending. Answering is still right: the caller has to learn that its post may land
// anyway rather than wait on a dependency that will never answer.
//
// The old HTTP service stopped the process here. This one must not: its caller replaces
// a dead child and retries, so exiting would turn one abandoned post into two.
class DeadlineExceeded extends PublisherError {
  constructor(id: number) {
    super(
      "internal",
      `submit exceeded the ${SUBMIT_TIMEOUT.ms} ms deadline; if it had reached submit the transaction ` +
        `may still land, so check the chain for request ${id} before retrying`,
    );
  }
}

/**
 * Balances, proves and submits one intent, and answers where it landed.
 *
 * ONE AT A TIME, NOT QUEUED: the wallet has a single dust UTXO, so a second concurrent
 * submit could only burn a prove and fail at balance ~35s later. The reader loop already
 * serializes requests; this gate is what still holds when a submit is abandoned at its
 * deadline and keeps running behind the answer.
 */
export async function handleSubmit(config: Config, id: number, intent: Uint8Array): Promise<Landed> {
  // Before the gate: a malformed intent must not cost the next caller its turn.
  const decoded = decodeIntent(intent);

  if (inFlightId !== undefined) {
    throw new PublisherError(
      "wallet_busy",
      `a submit for request ${inFlightId} holds the funding wallet; one at a time, ~35s each`,
    );
  }
  inFlightId = id;

  const work = post(config, decoded);
  // The gate follows the WORK, not the answer: an abandoned submit is still spending,
  // and releasing on the answer would put a second balance on the coin it has not
  // finished with.
  const release = (): void => {
    inFlightId = undefined;
  };
  void work.then(release, release);

  return withDeadline(work, SUBMIT_TIMEOUT.ms, () => new DeadlineExceeded(id));
}
