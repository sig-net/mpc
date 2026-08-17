// Mechanism, never authority: the signature was computed by the MPC threshold and the
// call decided by the caller, so the worst a bug here can do is drop a post or pay twice.

import {
  Intent,
  Transaction,
  type UnprovenIntent,
  type UnprovenTransaction,
} from "@midnightntwrk/ledger-v9";

import type { Config } from "./config.js";
import { describeFailure, PublisherError, type ErrorCode } from "./errors.js";
import { proveTransaction, type UnboundTransaction } from "./prover.js";
import { openFundingWallet, type FundingWallet, type Landed } from "./wallet.js";

export function decodeIntent(bytes: Uint8Array): UnprovenIntent {
  try {
    return Intent.deserialize("signature", "pre-proof", "pre-binding", bytes);
  } catch (cause) {
    throw new PublisherError("bad_request", `invalid request: \`intent\` did not deserialize`, {
      cause,
    });
  }
}

export interface Publisher {
  readonly proveTx: (tx: UnprovenTransaction, proofBudgetMs: number) => Promise<UnboundTransaction>;
  readonly wallet: FundingWallet;
}

// Every dependency below waits forever by default; unbounded, one would hold the busy gate silently.
export const SUBMIT_TIMEOUT_MS = 6 * 60 * 1000;
const SHUTDOWN_TIMEOUT_MS = 1_000;

// `Promise.race` handles the loser, so the abandoned attempt's own late failure surfaces nowhere.
async function withDeadline<T>(work: Promise<T>, ms: number, timeoutError: Error): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => void (timer = setTimeout(() => reject(timeoutError), ms))),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

let publisherPromise: Promise<Publisher> | undefined;

async function buildPublisher(config: Config): Promise<Publisher> {
  const endpoints = config.endpoints;
  return {
    proveTx: (tx, proofBudgetMs) => proveTransaction(endpoints.proofServerUrl, tx, proofBudgetMs),
    wallet: await openFundingWallet(config.accountKeys, config.networkId, endpoints),
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

export function warmupPublisher(config: Config): void {
  void publisher(config).catch(() => undefined);
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

export async function shutdownPublisher(): Promise<void> {
  await withDeadline(
    closePublisher(),
    SHUTDOWN_TIMEOUT_MS,
    new Error(`publisher cleanup exceeded ${SHUTDOWN_TIMEOUT_MS} ms`),
  ).catch(() => undefined);
}

// The only place this process matches on dependency error text. Both wallet_unfunded
// spellings mean back off. A node refusal carries no ledger reason on this side, only the
// SDK's `TransactionInvalidError` or the RPC's `Invalid Transaction` text: nothing was
// posted, rebuild against fresh state. `spend` treats any unclassified submit failure as
// ambiguous because the transaction may already have left this process.
const REFINEMENTS: readonly (readonly [pattern: string, code: ErrorCode])[] = [
  ["Wallet.InsufficientFunds", "wallet_unfunded"],
  ["could not balance dust", "wallet_unfunded"],
  ["TransactionInvalidError", "state_conflict"],
  ["Invalid Transaction", "state_conflict"],
];

function asPublisherError(error: unknown): PublisherError {
  if (error instanceof PublisherError) return error;
  const described = describeFailure(error);
  // Matched against a wider haystack than the answered message: Effect hides the real
  // cause on a Symbol that only `String` renders.
  const code = REFINEMENTS.find(([pattern]) =>
    `${described}\n${String(error)}`.includes(pattern),
  )?.[1];
  return new PublisherError(code ?? "internal", described, { cause: error });
}

function ambiguousSubmit(id: number, reason: string, cause?: unknown): PublisherError {
  return new PublisherError(
    "ambiguous_submit",
    `${reason}; the transaction may still land, so check the chain for request ${id} before retrying`,
    { cause },
  );
}

async function spend(ready: Publisher, proven: UnboundTransaction, id: number): Promise<Landed> {
  let finalized: Parameters<FundingWallet["submitTx"]>[0];
  try {
    const recipe = await ready.wallet.balanceTx(proven);
    finalized = await ready.wallet.finalizeTx(recipe);
  } catch (error) {
    throw asPublisherError(error);
  }
  try {
    return await ready.wallet.submitTx(finalized);
  } catch (error) {
    const classified = asPublisherError(error);
    if (classified.code !== "internal") throw classified;
    throw ambiguousSubmit(id, "transaction submission returned no definitive answer", error);
  }
}

let inFlightId: number | undefined;

/**
 * The stdio loop handles one request at a time. This gate remains after an ambiguous
 * answer while the underlying wallet work still owns the single DUST UTXO.
 */
export async function handleSubmit(
  config: Config,
  id: number,
  intent: Uint8Array,
): Promise<Landed> {
  const deadline = performance.now() + SUBMIT_TIMEOUT_MS;

  // Before the gate: a malformed intent must not cost the next caller its turn.
  const decoded = decodeIntent(intent);

  if (inFlightId !== undefined) {
    throw new PublisherError(
      "wallet_busy",
      `a submit for request ${inFlightId} holds the funding wallet; one at a time, ~35s each`,
    );
  }

  const preflightTimeout = new PublisherError(
    "wallet_unsynced",
    `funding wallet startup/readiness exceeded the ${SUBMIT_TIMEOUT_MS} ms submit deadline; ` +
      `nothing was posted and retry is safe`,
  );
  const remaining = (): number => Math.max(0, deadline - performance.now());

  let ready: Publisher;
  try {
    const startupBudgetMs = remaining();
    if (startupBudgetMs <= 0) throw preflightTimeout;
    ready = await withDeadline(publisher(config), startupBudgetMs, preflightTimeout);

    const readinessBudgetMs = remaining();
    if (readinessBudgetMs <= 0) throw preflightTimeout;
    await ready.wallet.requireReady(readinessBudgetMs);
  } catch (error) {
    throw asPublisherError(error);
  }

  const provingTimeout = new PublisherError(
    "proving_timeout",
    `the submit deadline expired before wallet work; no wallet operation started and retry is safe`,
  );
  const proofBudgetMs = remaining();
  if (proofBudgetMs <= 0) throw provingTimeout;

  let proven: UnboundTransaction;
  try {
    // No Zswap offer: a respond moves no coins, the wallet adds the fee inputs next.
    proven = await ready.proveTx(
      Transaction.fromParts(config.networkId, undefined, undefined, decoded),
      proofBudgetMs,
    );
  } catch (error) {
    throw asPublisherError(error);
  }

  if (remaining() <= 0) throw provingTimeout;

  inFlightId = id;
  const work = spend(ready, proven, id);
  // The gate follows the WORK, not the answer: an abandoned submit is still spending.
  const release = (): void => {
    inFlightId = undefined;
  };
  void work.then(release, release);

  // Balance, finalize and submit are not cancellable, so work past the deadline keeps
  // spending; the caller has to learn its post may land anyway.
  const timeout = ambiguousSubmit(id, `submit exceeded the ${SUBMIT_TIMEOUT_MS} ms deadline`);
  const answerBudgetMs = remaining();
  if (answerBudgetMs <= 0) throw timeout;
  return withDeadline(work, answerBudgetMs, timeout);
}
