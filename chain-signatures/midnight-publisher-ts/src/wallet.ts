// The funding (gas) wallet, and the only reason this process talks to an indexer:
// spendable DUST is derived by replaying ledger events, which no node RPC serves.

import {
  initialiseWalletFacade,
  type AccountKeys,
  type MidnightNodeConfig,
  type WalletFacade,
} from "@sig-net/midnight-contract-deploy";
import type { FinalizedTransaction } from "@midnightntwrk/ledger-v9";
import { filter, firstValueFrom, throwError, timeout } from "rxjs";

import { PublisherError } from "./errors.js";
import type { UnboundTransaction } from "./prover.js";

// Derived rather than imported: the type's home package would be a second copy of the wallet SDK.
export type BalancingRecipe = Awaited<ReturnType<WalletFacade["signRecipe"]>>;

export interface Landed {
  readonly txId: string;
}

export interface FundingWallet {
  requireReady(timeoutMs: number): Promise<void>;
  balanceTx(tx: UnboundTransaction): Promise<BalancingRecipe>;
  finalizeTx(recipe: BalancingRecipe): Promise<FinalizedTransaction>;
  submitTx(tx: FinalizedTransaction): Promise<Landed>;
  close(): Promise<void>;
}

// Also the dust intent's TTL: how long a submit dying between finalize and submit strands the coin.
export const RECIPE_TTL_MS = 5 * 60 * 1000;

class DustReadinessTimeoutError extends Error {}

export async function openFundingWallet(
  keys: AccountKeys,
  config: MidnightNodeConfig,
): Promise<FundingWallet> {
  const facade = await initialiseWalletFacade(keys, config);

  try {
    await facade.start(keys.shieldedSecretKeys, keys.dustSecretKey);
  } catch (error) {
    await facade.stop().catch(() => undefined);
    throw error;
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
    close: () => facade.stop(),
  };
}
