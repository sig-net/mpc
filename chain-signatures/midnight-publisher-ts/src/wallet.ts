// The funding (gas) wallet, and the only reason this process talks to an indexer:
// spendable DUST is derived by replaying ledger events, which no node RPC serves.

import {
  defaultAdditionalFeeOverhead,
  initialiseWalletFacade,
  type AccountKeys,
  type MidnightNodeConfig,
} from "@sig-net/midnight-contract-deploy";
import type { FinalizedTransaction } from "@midnightntwrk/ledger-v9";
import { InMemoryTransactionHistoryStorage } from "@midnightntwrk/wallet-sdk-abstractions";
import { DustWallet } from "@midnightntwrk/wallet-sdk-dust-wallet";
import {
  mergeWalletEntries,
  WalletEntrySchema,
  WalletFacade,
  type BalancingRecipe,
  type FacadeState,
} from "@midnightntwrk/wallet-sdk-facade";
import { ShieldedWallet } from "@midnightntwrk/wallet-sdk-shielded";
import { UnshieldedWallet } from "@midnightntwrk/wallet-sdk-unshielded-wallet";
import { filter, firstValueFrom, of, ReplaySubject, throwError, timeout } from "rxjs";

import type { Endpoints } from "./config.js";
import { latestDustEventId } from "./dust-probe.js";
import { nodeRpc, watchLanding } from "./landing.js";
import { describeFailure, PublisherError } from "./errors.js";
import type { UnboundTransaction } from "./prover.js";
import { decodeSnapshot, encodeSnapshot, type WalletSnapshot } from "./snapshot.js";

export type { BalancingRecipe };

export interface Landed {
  readonly txId: string;
  /** Spendable DUST in SPECK, read before the spend; absent if the wallet could not say. */
  readonly dustBalance?: bigint;
}

export interface FundingWallet {
  requireReady(timeoutMs: number): Promise<void>;
  /**
   * Resyncs the wallet first if the indexer holds DUST events it has not applied: spends
   * proven against a stale DUST tree are refused. Never posts; refuses `wallet_unsynced`.
   */
  ensureCurrent(timeoutMs: number): Promise<void>;
  dustBalance(): Promise<bigint | undefined>;
  balanceTx(tx: UnboundTransaction): Promise<BalancingRecipe>;
  finalizeTx(recipe: BalancingRecipe): Promise<FinalizedTransaction>;
  submitTx(tx: FinalizedTransaction): Promise<Landed>;
  /** The encoded sub-wallet states; refused until synced with every submission settled. */
  snapshot(): Promise<string>;
  /** The coins and sync progress on one line, for a log; never throws. */
  describe(): Promise<string>;
  close(): Promise<void>;
}

// Also the dust intent's TTL: how long a submit dying between finalize and submit strands the coin.
export const RECIPE_TTL_MS = 5 * 60 * 1000;

class DustReadinessTimeoutError extends Error {}

// Short: the figure only feeds the node's metric.
const DUST_BALANCE_READ_MS = 1_000;

// Never throws: a post must not fail over its balance.
async function readDustBalance(facade: WalletFacade): Promise<bigint | undefined> {
  try {
    const state = await firstValueFrom(
      facade.dust.state.pipe(timeout({ first: DUST_BALANCE_READ_MS, with: () => of(undefined) })),
    );
    return state?.progress.isStrictlyComplete() ? state.balance(new Date()) : undefined;
  } catch {
    return undefined;
  }
}

// `initialiseWalletFacade`'s facade with each sub-wallet restored rather than started empty.
// Keep the configuration in step with it: only the wallet constructors may differ.
const FEE_BLOCKS_MARGIN = 5;

async function restoreWalletFacade(
  config: MidnightNodeConfig,
  snapshot: WalletSnapshot,
): Promise<WalletFacade> {
  const configuration = {
    networkId: config.networkId,
    indexerClientConnection: {
      indexerHttpUrl: config.indexerUrl,
      indexerWsUrl: config.indexerWsUrl,
    },
    provingServerUrl: new URL(config.proofServerUrl),
    relayURL: new URL(config.nodeUrl.replace(/^http/, "ws")),
    costParameters: {
      additionalFeeOverhead: defaultAdditionalFeeOverhead(config.networkId),
      feeBlocksMargin: FEE_BLOCKS_MARGIN,
    },
    txHistoryStorage: new InMemoryTransactionHistoryStorage(WalletEntrySchema, mergeWalletEntries),
  };
  // Restored before `init`, which opens the node connection first and has nothing to close
  // it with when a wallet factory throws, as `restore` does on state it cannot decode.
  const restored: { stop(): Promise<void> }[] = [];
  try {
    const shielded = ShieldedWallet(configuration).restore(snapshot.shielded);
    restored.push(shielded);
    const unshielded = UnshieldedWallet(configuration).restore(snapshot.unshielded);
    restored.push(unshielded);
    const dust = DustWallet(configuration).restore(snapshot.dust);
    restored.push(dust);
    return await WalletFacade.init({
      configuration,
      shielded: () => shielded,
      unshielded: () => unshielded,
      dust: () => dust,
    });
  } catch (error) {
    await Promise.all(restored.map((wallet) => wallet.stop().catch(() => undefined)));
    throw error;
  }
}

async function startFacade(
  keys: AccountKeys,
  config: MidnightNodeConfig,
  snapshot: WalletSnapshot | undefined,
): Promise<WalletFacade> {
  const facade =
    snapshot === undefined
      ? await initialiseWalletFacade(keys, config)
      : await restoreWalletFacade(config, snapshot);
  try {
    await facade.start(keys.shieldedSecretKeys, keys.dustSecretKey);
  } catch (error) {
    await facade.stop().catch(() => undefined);
    throw error;
  }
  return facade;
}

// A restored wallet only replays what happened since its snapshot, which takes seconds; one
// that makes no progress against an answering indexer for this long falls back to a full sync
// rather than holding the publisher.
const RESTORED_SYNC_TIMEOUT_MS = 3 * 60 * 1000;
// The SDK retries a failed indexer subscription on a backoff that grows to two minutes, so a
// restore begun during an indexer outage can stay offline that long after the indexer is
// back; one with no progress over this interval while the indexer answers is restarted from
// the snapshot, which reconnects at once.
const RESTORE_PROGRESS_CHECK_MS = 10_000;
const INDEXER_PROBE_MS = 2_000;

const DESCRIBE_TIMEOUT_MS = 1_000;
// How long the indexer gets to report its latest DUST event over a fresh socket.
const DUST_PROBE_MS = 3_000;
// How long the wallet gets to apply events the probe saw before it counts as stale: its
// own sockets receive a new block's events when the probe does.
const DUST_CATCH_UP_MS = 5_000;
// Restoring from the wallet's own current state replays seconds of events.
const RESYNC_BUDGET_MS = 60_000;
// The SDK hears of finality from its own subscription; past this after the node, it never will.
const SDK_ANSWER_GRACE_MS = 2_000;
// How long a reopen waits for the landed transaction to settle, so the restored state does
// not carry its coin as in flight.
const REOPEN_SETTLE_MS = 30_000;
// A submit returns before the wallet's own sync has seen its transaction confirmed, about a
// second later; a node publishing back to back is only ever asked inside that second.
const SNAPSHOT_SETTLE_MS = 5_000;

const seconds = (sinceMs: number): string => `${((Date.now() - sinceMs) / 1_000).toFixed(1)}s`;

// Whether a snapshot holds no coin booked by a transaction still in flight: the "settled"
// test of the Midnight DUST guide, over every sub-wallet's coins and without its
// spendable-DUST clause, which says when to build next rather than what may be kept.
function isSettled(state: FacadeState): boolean {
  return (
    state.isSynced &&
    state.pending.all.length === 0 &&
    [state.shielded, state.unshielded, state.dust].every(
      (wallet) => wallet.pendingCoins.length === 0,
    )
  );
}

function describeState(state: FacadeState): string {
  const { dust, shielded, unshielded } = state;
  return [
    `synced=${state.isSynced} pendingTxs=${state.pending.all.length}`,
    `dust(spendable=${dust.availableCoins.length} inFlight=${dust.pendingCoins.length} ` +
      `specks=${dust.balance(new Date())} ` +
      `applied=${dust.progress.appliedIndex}/${dust.progress.highestIndex} ` +
      `connected=${dust.progress.isConnected})`,
    `shielded(inFlight=${shielded.pendingCoins.length} ` +
      `applied=${shielded.progress.appliedIndex}/${shielded.progress.highestIndex} ` +
      `connected=${shielded.progress.isConnected})`,
    `unshielded(inFlight=${unshielded.pendingCoins.length} ` +
      `applied=${unshielded.progress.appliedId}/${unshielded.progress.highestTransactionId} ` +
      `connected=${unshielded.progress.isConnected})`,
  ].join(" ");
}

// Fire and forget: the log line is the only consumer, and a wallet that never syncs says so
// through `wallet_unsynced` instead.
function logWhenSynced(facade: WalletFacade, startedMs: number): void {
  firstValueFrom(facade.state().pipe(filter((state) => state.isSynced))).then(
    () => console.error(`funding wallet synced from the start in ${seconds(startedMs)}`),
    () => undefined,
  );
}

async function syncFromStart(keys: AccountKeys, config: MidnightNodeConfig): Promise<WalletFacade> {
  const startedMs = Date.now();
  const facade = await startFacade(keys, config, undefined);
  logWhenSynced(facade, startedMs);
  return facade;
}

// Whether the indexer answers a GraphQL request at all; never throws.
async function indexerAnswers(indexerUrl: string): Promise<boolean> {
  try {
    const response = await fetch(indexerUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ query: "{ __typename }" }),
      signal: AbortSignal.timeout(INDEXER_PROBE_MS),
    });
    await response.body?.cancel();
    return response.ok;
  } catch {
    return false;
  }
}

async function currentStates(facade: WalletFacade): Promise<WalletSnapshot> {
  return {
    shielded: await facade.shielded.serializeState(),
    unshielded: await facade.unshielded.serializeState(),
    dust: await facade.dust.serializeState(),
  };
}

function appliedMark(state: FacadeState): string {
  const { dust, shielded, unshielded } = state;
  return `${shielded.progress.appliedIndex}/${unshielded.progress.appliedId}/${dust.progress.appliedIndex}`;
}

// Starts the restored facade, and again from where it got to each time it stalls against an
// answering indexer. Throws once it has stalled for RESTORED_SYNC_TIMEOUT_MS in total. An
// unreachable indexer never counts: a full sync could not get further.
async function restoreUntilSynced(
  keys: AccountKeys,
  config: MidnightNodeConfig,
  snapshot: WalletSnapshot,
): Promise<WalletFacade> {
  let stalledMs = 0;
  let states = snapshot;
  // Kept across restarts, which resume where the last one stalled.
  let mark: string | undefined;
  for (;;) {
    const facade = await startFacade(keys, config, states);
    // One subscription for the whole wait, so no state lands between two reads of it.
    const latestState = new ReplaySubject<FacadeState>(1);
    const subscription = facade.state().subscribe(latestState);
    try {
      for (;;) {
        const synced = await firstValueFrom(
          latestState.pipe(
            filter((state) => state.isSynced),
            timeout({ first: RESTORE_PROGRESS_CHECK_MS, with: () => of(undefined) }),
          ),
          { defaultValue: undefined },
        );
        if (synced !== undefined) return facade;
        const latest = await firstValueFrom(
          latestState.pipe(timeout({ first: DESCRIBE_TIMEOUT_MS, with: () => of(undefined) })),
          { defaultValue: undefined },
        );
        const now = latest === undefined ? mark : appliedMark(latest);
        if (now !== mark) {
          mark = now;
          continue;
        }
        if (!(await indexerAnswers(config.indexerUrl))) continue;
        stalledMs += RESTORE_PROGRESS_CHECK_MS;
        if (stalledMs >= RESTORED_SYNC_TIMEOUT_MS) {
          throw new Error(`no sync progress in ${stalledMs} ms against an answering indexer`);
        }
        console.error(
          `restarting the wallet restore: no sync progress in ${RESTORE_PROGRESS_CHECK_MS} ms ` +
            `while the indexer answers`,
        );
        // Unreadable state only costs the replay since the snapshot.
        states = await currentStates(facade).catch(() => states);
        break;
      }
    } catch (error) {
      await facade.stop().catch(() => undefined);
      throw error;
    } finally {
      subscription.unsubscribe();
    }
    await facade.stop().catch(() => undefined);
  }
}

// Any snapshot problem costs a full sync, never a refusal: the snapshot only saves time.
async function startFromSnapshot(
  keys: AccountKeys,
  config: MidnightNodeConfig,
  owner: string,
  encoded: string | undefined,
): Promise<WalletFacade> {
  if (encoded === undefined) return syncFromStart(keys, config);
  const decoded = decodeSnapshot(encoded, config.networkId, owner);
  if ("rejected" in decoded) {
    console.error(`ignoring the wallet snapshot (${decoded.rejected}); syncing from the start`);
    return syncFromStart(keys, config);
  }
  const startedMs = Date.now();
  try {
    const facade = await restoreUntilSynced(keys, config, decoded.states);
    console.error(
      `funding wallet restored from a snapshot taken ${seconds(decoded.takenAt.getTime())} ` +
        `ago; caught up in ${seconds(startedMs)}`,
    );
    return facade;
  } catch (error) {
    console.error(
      `restoring the wallet snapshot failed (${describeFailure(error)}); syncing from the start`,
    );
    return syncFromStart(keys, config);
  }
}

async function openFacade(
  keys: AccountKeys,
  config: MidnightNodeConfig,
  snapshot: string | undefined,
): Promise<FundingWallet> {
  const owner = keys.unshieldedKeystore.getBech32Address().asString();
  let facade = await startFromSnapshot(keys, config, owner, snapshot);
  let closed = false;
  // A replacement restoring next to the stale facade, which stays in use until it is synced.
  let resyncing: Promise<void> | undefined;

  // `stale`: the indexer sockets fell behind. `silent`: the node socket stopped answering,
  // and a restored facade opens a new one.
  function resync(reason: "stale" | "silent"): Promise<void> {
    resyncing ??= (async () => {
      const startedMs = Date.now();
      try {
        if (reason === "silent") {
          const settled = await firstValueFrom(
            facade
              .state()
              .pipe(
                filter(isSettled),
                timeout({ first: REOPEN_SETTLE_MS, with: () => of(undefined) }),
              ),
            { defaultValue: undefined },
          );
          if (settled === undefined) {
            console.error(
              `not reopening the funding wallet: still unsettled after ${REOPEN_SETTLE_MS} ms`,
            );
            return;
          }
        }
        const fresh = await restoreUntilSynced(keys, config, await currentStates(facade));
        if (closed) {
          await fresh.stop().catch(() => undefined);
          return;
        }
        const stale = facade;
        facade = fresh;
        console.error(
          `funding wallet ${reason === "stale" ? "resynced" : "reopened"} in ${seconds(startedMs)}`,
        );
        await stale.stop().catch(() => undefined);
      } catch (error) {
        // The stale facade stays; the next submit's check tries again.
        console.error(`resyncing the funding wallet failed (${describeFailure(error)})`);
      } finally {
        resyncing = undefined;
      }
    })();
    return resyncing;
  }

  async function awaitResync(pending: Promise<void>, timeoutMs: number): Promise<void> {
    const unsynced = new PublisherError(
      "wallet_unsynced",
      `the funding wallet was still resyncing after ${timeoutMs} ms; nothing was posted`,
    );
    let timer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        pending,
        new Promise<never>(
          (_, reject) => void (timer = setTimeout(() => reject(unsynced), timeoutMs)),
        ),
      ]);
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    async requireReady(timeoutMs) {
      try {
        await firstValueFrom(
          facade.dust.state.pipe(
            filter((state) => state.progress.isStrictlyComplete()),
            timeout({
              first: timeoutMs,
              with: () => throwError(() => new DustReadinessTimeoutError()),
            }),
          ),
        );
      } catch (error) {
        if (!(error instanceof DustReadinessTimeoutError)) throw error;
        throw new PublisherError(
          "wallet_unsynced",
          `DUST indexing is still catching up after ${timeoutMs} ms; nothing was posted`,
          { cause: error },
        );
      }
    },
    async ensureCurrent(timeoutMs) {
      const budgetMs = Math.min(timeoutMs, RESYNC_BUDGET_MS);
      const pending = resyncing;
      if (pending !== undefined) return awaitResync(pending, budgetMs);
      const startedMs = Date.now();
      const dust = facade.dust.state;
      const applied = (
        await firstValueFrom(
          dust.pipe(timeout({ first: DESCRIBE_TIMEOUT_MS, with: () => of(undefined) })),
          { defaultValue: undefined },
        )
      )?.progress.appliedIndex;
      if (applied === undefined) return;
      const latest = await latestDustEventId(config.indexerWsUrl, applied, DUST_PROBE_MS);
      // An indexer that does not answer leaves nothing to compare: submit as before.
      if (latest === undefined || latest <= applied) return;
      const caughtUp = await firstValueFrom(
        dust.pipe(
          filter((state) => state.progress.appliedIndex >= latest),
          timeout({ first: DUST_CATCH_UP_MS, with: () => of(undefined) }),
        ),
        { defaultValue: undefined },
      );
      if (caughtUp !== undefined) return;
      console.error(
        `funding wallet DUST is behind the indexer (applied ${applied}, indexer at ${latest}, ` +
          `checked in ${seconds(startedMs)}); resyncing before the submit`,
      );
      return awaitResync(resync("stale"), budgetMs);
    },
    dustBalance: () => readDustBalance(facade),
    async balanceTx(tx) {
      const secretKeys = {
        shieldedSecretKeys: keys.shieldedSecretKeys,
        dustSecretKey: keys.dustSecretKey,
      };
      const recipe = await facade.balanceUnboundTransaction(tx, secretKeys, {
        ttl: new Date(Date.now() + RECIPE_TTL_MS),
        tokenKindsToBalance: ["dust"],
      });
      return facade.signRecipe(recipe, keys.unshieldedKeystore.signDataAsync);
    },
    finalizeTx: (recipe) => facade.finalizeRecipe(recipe),
    async submitTx(tx) {
      if (tx.identifiers().at(-1) === undefined) {
        throw new Error("the finalized transaction carries no identifier");
      }
      // The SDK answers only from its node subscription, which a dropped or frozen socket
      // ends silently; the node itself says whether the transaction went anywhere.
      const watch = watchLanding(
        nodeRpc(config.nodeUrl),
        Buffer.from(tx.serialize()).toString("hex"),
        tx.identifiers().at(-1)!,
      );
      const fromSdk = facade.submitTransaction(tx);
      try {
        const answer = await Promise.race([
          fromSdk.then((txId) => ({ txId, fromNode: false })),
          watch.verdict.then((txId) => ({ txId, fromNode: true })),
        ]);
        if (answer.txId === undefined) {
          throw new Error("the finalized transaction carries no identifier");
        }
        if (answer.fromNode) {
          const late = await Promise.race([
            fromSdk.then(
              () => false,
              () => false,
            ),
            new Promise<boolean>((resolve) => setTimeout(() => resolve(true), SDK_ANSWER_GRACE_MS)),
          ]);
          if (late) {
            // Its next submit would go out on the same dead socket.
            console.error(
              `the node finalized ${answer.txId} but the SDK never answered; reopening the wallet`,
            );
            void resync("silent");
          }
        }
        return { txId: answer.txId };
      } finally {
        watch.stop();
      }
    },
    async snapshot() {
      if (resyncing !== undefined) {
        throw new PublisherError("wallet_busy", "the funding wallet is resyncing");
      }
      const state = await firstValueFrom(facade.state());
      if (!state.isSynced) {
        throw new PublisherError("wallet_unsynced", "the funding wallet has not finished syncing");
      }
      // A restored wallet keeps an in-flight coin unspendable until its transaction settles or
      // expires, so a snapshot holding one would carry the stall into every restart.
      const settled = isSettled(state)
        ? state
        : await firstValueFrom(
            facade
              .state()
              .pipe(
                filter(isSettled),
                timeout({ first: SNAPSHOT_SETTLE_MS, with: () => of(undefined) }),
              ),
            { defaultValue: undefined },
          );
      if (settled === undefined) {
        throw new PublisherError(
          "wallet_busy",
          `the funding wallet still had a submission in flight after ${SNAPSHOT_SETTLE_MS} ms: ` +
            describeState(state),
        );
      }
      return encodeSnapshot(
        config.networkId,
        owner,
        {
          shielded: await facade.shielded.serializeState(),
          unshielded: await facade.unshielded.serializeState(),
          dust: await facade.dust.serializeState(),
        },
        new Date(),
      );
    },
    async describe() {
      try {
        const state = await firstValueFrom(
          facade.state().pipe(timeout({ first: DESCRIBE_TIMEOUT_MS })),
        );
        return describeState(state);
      } catch (error) {
        return `unavailable (${describeFailure(error)})`;
      }
    },
    close: () => {
      closed = true;
      return facade.stop();
    },
  };
}

export async function openFundingWallet(
  keys: AccountKeys,
  networkId: string,
  endpoints: Endpoints,
  snapshot?: string,
): Promise<FundingWallet> {
  return openFacade(
    keys,
    {
      indexerUrl: endpoints.indexerUrl,
      indexerWsUrl: endpoints.indexerWsUrl,
      nodeUrl: endpoints.nodeUrl,
      proofServerUrl: endpoints.proofServerUrl,
      networkId,
    },
    snapshot,
  );
}
