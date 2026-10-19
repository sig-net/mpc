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
import { filter, firstValueFrom, throwError, timeout } from "rxjs";

import type { Endpoints } from "./config.js";
import { describeFailure, PublisherError } from "./errors.js";
import type { UnboundTransaction } from "./prover.js";
import { decodeSnapshot, encodeSnapshot, type WalletSnapshot } from "./snapshot.js";

export type { BalancingRecipe };

export interface Landed {
  readonly txId: string;
}

export interface FundingWallet {
  requireReady(timeoutMs: number): Promise<void>;
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
// still behind after a full sync's worth of time is not going to catch up.
const RESTORED_SYNC_TIMEOUT_MS = 10 * 60 * 1000;

const DESCRIBE_TIMEOUT_MS = 1_000;

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
    const facade = await startFacade(keys, config, decoded.states);
    try {
      await firstValueFrom(
        facade.state().pipe(
          filter((state) => state.isSynced),
          timeout({ first: RESTORED_SYNC_TIMEOUT_MS }),
        ),
      );
    } catch (error) {
      await facade.stop().catch(() => undefined);
      throw error;
    }
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
  const facade = await startFromSnapshot(keys, config, owner, snapshot);

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
      const txId = await facade.submitTransaction(tx);
      if (txId === undefined) throw new Error("the finalized transaction carries no identifier");
      return { txId };
    },
    async snapshot() {
      const state = await firstValueFrom(facade.state());
      if (!state.isSynced) {
        throw new PublisherError("wallet_unsynced", "the funding wallet has not finished syncing");
      }
      // A restored wallet keeps an in-flight coin unspendable until its transaction settles or
      // expires, so a snapshot holding one would carry the stall into every restart.
      if (!isSettled(state)) {
        throw new PublisherError(
          "wallet_busy",
          `the funding wallet has a submission in flight: ${describeState(state)}`,
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
    close: () => facade.stop(),
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
