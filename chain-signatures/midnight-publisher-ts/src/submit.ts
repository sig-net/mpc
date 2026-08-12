// Mechanism, never authority: the signature was computed by the MPC threshold and the
// call decided by the caller, so the worst a bug here can do is drop a post or pay twice.

import { Intent, Transaction, type UnprovenIntent, type UnprovenTransaction } from "@midnightntwrk/ledger-v9";

import { SUBMIT_VAR_NAMES, type Config } from "./config.js";
import { describeFailure, PublisherError, type ErrorCode } from "./errors.js";
import { proveTransaction, type UnboundTransaction } from "./prover.js";
import { openFundingWallet, type FundingWallet, type Landed } from "./wallet.js";

// The Rust half writes these bytes with its own ledger crate; the tag is where a version split surfaces.
const INTENT_TAG = "midnight:intent[v9]";

const TAG_WINDOW = 64;

export function decodeIntent(bytes: Uint8Array): UnprovenIntent {
  const head = Buffer.from(bytes.subarray(0, TAG_WINDOW)).toString("latin1");
  if (!head.includes(INTENT_TAG)) {
    throw new PublisherError("bad_request", `invalid request: \`intent\` is not a ${INTENT_TAG} blob`);
  }

  try {
    return Intent.deserialize("signature", "pre-proof", "pre-binding", bytes);
  } catch (cause) {
    throw new PublisherError("bad_request", `invalid request: \`intent\` did not deserialize`, { cause });
  }
}

export interface Publisher {
  readonly proveTx: (tx: UnprovenTransaction) => Promise<UnboundTransaction>;
  readonly wallet: FundingWallet;
}

// Every dependency below waits forever by default; unbounded, one would hold the busy gate silently.
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
    proveTx: (tx) => proveTransaction(endpoints.proofServerUrl, tx),
    wallet: await openFundingWallet(config.networkId, endpoints),
  };
}

// Memoized even while pending, so a hung indexer costs one wallet facade, not one per retry.
function publisher(config: Config): Promise<Publisher> {
  publisherPromise ??= buildPublisher(config).catch((error: unknown) => {
    publisherPromise = undefined;
    throw error;
  });
  return publisherPromise;
}

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

// The only place this process matches on dependency error text; both wallet_unfunded
// spellings mean back off, ReadMismatch means rebuild against fresh state.
const REFINEMENTS: readonly (readonly [pattern: string, code: ErrorCode])[] = [
  ["Wallet.InsufficientFunds", "wallet_unfunded"],
  ["could not balance dust", "wallet_unfunded"],
  ["ReadMismatch", "state_conflict"],
];

async function post(config: Config, intent: UnprovenIntent): Promise<Landed> {
  try {
    const ready = await publisher(config);
    // No Zswap offer: a respond moves no coins, the wallet adds the fee inputs next.
    const proven = await ready.proveTx(Transaction.fromParts(config.networkId, undefined, undefined, intent));
    const recipe = await ready.wallet.balanceTx(proven);
    const finalized = await ready.wallet.finalizeTx(recipe);
    return await ready.wallet.submitTx(finalized);
  } catch (error) {
    if (error instanceof PublisherError) throw error;
    const described = describeFailure(error);
    // Matched against a wider haystack than the answered message: Effect hides the real
    // cause on a Symbol that only `String` renders.
    const code = REFINEMENTS.find(([pattern]) => `${described}\n${String(error)}`.includes(pattern))?.[1];
    throw new PublisherError(code ?? "internal", described, { cause: error });
  }
}

let inFlightId: number | undefined;

/**
 * One at a time: the wallet has a single dust UTXO, so a second concurrent submit could
 * only burn a prove and fail at balance ~35s later.
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
  // The gate follows the WORK, not the answer: an abandoned submit is still spending.
  const release = (): void => {
    inFlightId = undefined;
  };
  void work.then(release, release);

  // Nothing below the wallet is cancellable, so a submit past its deadline keeps
  // spending; the caller has to learn its post may land anyway.
  return withDeadline(
    work,
    SUBMIT_TIMEOUT.ms,
    () =>
      new PublisherError(
        "internal",
        `submit exceeded the ${SUBMIT_TIMEOUT.ms} ms deadline; if it had reached submit the transaction ` +
          `may still land, so check the chain for request ${id} before retrying`,
      ),
  );
}
