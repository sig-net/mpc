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
// The settled value of `publisherPromise`, for callers that must not wait on a sync.
let openedPublisher: Publisher | undefined;
// Handed over by `ready`; every wallet this process opens resumes from it.
let walletSnapshot: string | undefined;

async function buildPublisher(config: Config): Promise<Publisher> {
  const endpoints = config.endpoints;
  return {
    proveTx: (tx, proofBudgetMs) => proveTransaction(endpoints.proofServerUrl, tx, proofBudgetMs),
    wallet: await openFundingWallet(
      config.accountKeys,
      config.networkId,
      endpoints,
      walletSnapshot,
    ),
  };
}

function remember(pending: Promise<Publisher>): Promise<Publisher> {
  publisherPromise = pending;
  void pending.then(
    (ready) => {
      if (publisherPromise === pending) openedPublisher = ready;
    },
    () => undefined,
  );
  return pending;
}

// Memoized even while pending, so a hung indexer costs one wallet facade, not one per retry.
function publisher(config: Config): Promise<Publisher> {
  return (
    publisherPromise ??
    remember(
      buildPublisher(config).catch((error: unknown) => {
        publisherPromise = undefined;
        throw error;
      }),
    )
  );
}

export function warmupPublisher(config: Config, snapshot?: string): void {
  walletSnapshot = snapshot;
  void publisher(config).catch(() => undefined);
}

export function primePublisher(ready: Promise<Publisher>): void {
  void remember(ready);
}

/** The opened wallet's snapshot; refused while it syncs or a submit still owns it or its coins. */
export async function snapshotWallet(): Promise<string> {
  if (inFlightId !== undefined) {
    throw new PublisherError(
      "wallet_busy",
      `a submit for request ${inFlightId} holds the funding wallet; snapshot after it settles`,
    );
  }
  const wallet = openedPublisher?.wallet;
  if (wallet === undefined) {
    throw new PublisherError("wallet_unsynced", "the funding wallet has not finished syncing");
  }
  return wallet.snapshot();
}

export async function closePublisher(): Promise<void> {
  const pending = publisherPromise;
  publisherPromise = undefined;
  openedPublisher = undefined;
  walletSnapshot = undefined;
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
// SDK's `TransactionInvalidError`, the RPC's `Invalid Transaction` text, or its `1002`
// when the node fails to validate the transaction at all: nothing was posted, rebuild
// against fresh state. `spend` treats any unclassified submit failure as ambiguous
// because the transaction may already have left this process.
const REFINEMENTS: readonly (readonly [pattern: string, code: ErrorCode])[] = [
  ["Wallet.InsufficientFunds", "wallet_unfunded"],
  ["could not balance dust", "wallet_unfunded"],
  ["TransactionInvalidError", "state_conflict"],
  ["Invalid Transaction", "state_conflict"],
  ["1002: Verification Error", "state_conflict"],
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

function ambiguousSubmit(reason: string, cause?: unknown): PublisherError {
  return new PublisherError(
    "ambiguous_submit",
    `${reason}; the transaction may still land, and the MPC retries automatically, so it may publish the response more than once; duplicate response posts are safe`,
    { cause },
  );
}

async function spend(ready: Publisher, proven: UnboundTransaction): Promise<Landed> {
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
    throw ambiguousSubmit("transaction submission returned no definitive answer", error);
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
  try {
    return await submitOnce(config, id, intent);
  } catch (error) {
    throw await withWalletState(error);
  }
}

// The parent retires this process after most refused submits, so the refusal is the only
// record left of the wallet that caused it.
async function withWalletState(error: unknown): Promise<PublisherError> {
  const failure = asPublisherError(error);
  const wallet = openedPublisher?.wallet;
  if (wallet === undefined || failure.code === "bad_request") return failure;
  return new PublisherError(failure.code, failure.message, {
    cause: failure.cause,
    walletState: await wallet.describe(),
    walletUsed: failure.walletUsed,
  });
}

// Only a failure from here on can say anything about the wallet a snapshot restored.
function walletFailure(error: unknown): PublisherError {
  const failure = asPublisherError(error);
  return new PublisherError(failure.code, failure.message, {
    cause: failure.cause,
    walletUsed: true,
  });
}

async function submitOnce(config: Config, id: number, intent: Uint8Array): Promise<Landed> {
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
  // Before the spend: once balanced, the wallet's single coin reads as spent until the
  // change confirms.
  const dustBalance = await ready.wallet.dustBalance();

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
  const work = spend(ready, proven);
  // The gate follows the WORK, not the answer: an abandoned submit is still spending.
  const release = (): void => {
    inFlightId = undefined;
  };
  void work.then(release, release);

  // Balance, finalize and submit are not cancellable, so work past the deadline keeps
  // spending; the caller has to learn its post may land anyway.
  const timeout = ambiguousSubmit(`submit exceeded the ${SUBMIT_TIMEOUT_MS} ms deadline`);
  const answerBudgetMs = remaining();
  try {
    if (answerBudgetMs <= 0) throw timeout;
    const landed = await withDeadline(work, answerBudgetMs, timeout);
    return { ...landed, dustBalance };
  } catch (error) {
    throw walletFailure(error);
  }
}
