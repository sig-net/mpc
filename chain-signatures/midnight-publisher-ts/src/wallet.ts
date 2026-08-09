// The funding (gas) wallet, and THE ONLY REASON THIS PROCESS TALKS TO AN INDEXER: no
// node RPC returns UTXO or dust state for an address, and spendable DUST exists only
// after replaying every block's ledger events from genesis with that wallet's secret
// key. It pays fees and decides nothing, so it sits downstream of every security
// decision the caller already made.

import {
  deriveAccountKeys,
  initialiseWalletFacade,
  parseSeed,
  SeedFormat,
  type AccountKeys,
  type MidnightNodeConfig,
  type WalletFacade,
} from "@sig-net/midnight-contract-deploy";
import type { FinalizedTransaction } from "@midnightntwrk/ledger-v9";

import { fundingSeed, type Endpoints } from "./config.js";
import type { UnboundTransaction } from "./prover.js";

// The facade's balancing plan, taken off the facade rather than imported: the type
// lives in a package this one does not depend on directly, and a second copy of the
// wallet SDK at a different version is a worse problem than a derived type.
export type BalancingRecipe = Awaited<ReturnType<WalletFacade["signRecipe"]>>;

/** Where a submitted transaction landed. Both bare lowercase hex, as the rest of the wire is. */
export interface Landed {
  readonly txId: string;
  readonly blockHash: string;
}

export interface FundingWallet {
  /** Adds the fee inputs and signs what they added. */
  balanceTx(tx: UnboundTransaction, ttl?: Date): Promise<BalancingRecipe>;
  /** Binds the call and proves the balancing the wallet added, on the same proof server. */
  finalizeTx(recipe: BalancingRecipe): Promise<FinalizedTransaction>;
  submitTx(tx: FinalizedTransaction): Promise<Landed>;
  close(): Promise<void>;
}

// Also the dust intent's TTL: how long a submit dying between finalize and submit strands the coin.
const RECIPE_TTL_MS = 5 * 60 * 1000;

// Hex only. The message names the env var and never quotes the value.
export function parseFundingSeed(seed: string): Uint8Array {
  try {
    const parsed = parseSeed(seed);
    if (parsed.source.format === SeedFormat.Hex) return parsed.seed;
  } catch {
    // The lib's ParseError describes shapes; ours must name the env var instead.
  }
  throw new Error("MIDNIGHT_PUB_FUNDING_SEED must be hex (16 to 64 bytes); a mnemonic is not accepted");
}

export function deriveFundingKeys(seed: string, networkId: string): AccountKeys {
  // Not redundant: `deriveAccountKeys` also accepts a BIP-39 mnemonic and
  // PBKDF2s it into a different, unfunded wallet.
  parseFundingSeed(seed);
  return deriveAccountKeys(seed, networkId);
}

export function nodeConfig(networkId: string, endpoints: Endpoints): MidnightNodeConfig {
  return {
    indexerUrl: endpoints.indexerUrl,
    indexerWsUrl: endpoints.indexerWsUrl,
    nodeUrl: endpoints.nodeUrl,
    proofServerUrl: endpoints.proofServerUrl,
    networkId,
  };
}

async function openFacade(keys: AccountKeys, config: MidnightNodeConfig): Promise<FundingWallet> {
  const facade = await initialiseWalletFacade(keys, config);

  await facade.start(keys.shieldedSecretKeys, keys.dustSecretKey);
  await facade.waitForSyncedState();

  return {
    // The interface allows a `ttl`; honour it rather than silently dropping it.
    async balanceTx(tx, ttl) {
      const secretKeys = { shieldedSecretKeys: keys.shieldedSecretKeys, dustSecretKey: keys.dustSecretKey };
      const recipe = await facade.balanceUnboundTransaction(tx, secretKeys, {
        ttl: ttl ?? new Date(Date.now() + RECIPE_TTL_MS),
      });
      return facade.signRecipe(recipe, keys.unshieldedKeystore.signDataAsync);
    },
    finalizeTx: (recipe) => facade.finalizeRecipe(recipe),
    // The submission service rather than `facade.submitTransaction`, which waits for
    // this same `Finalized` event and then discards it, answering with the identifier
    // alone. The landing block is half of what this process owes its caller. What that
    // skips is one history entry nothing here reads: the pending transaction was already
    // registered by `finalizeRecipe`, and the revert below is the facade's own.
    async submitTx(tx) {
      // Typed non-optional by the facade, which reads the same list; a transaction with
      // no identifier would be one nothing can be watched by.
      const txId = tx.identifiers().at(-1);
      if (txId === undefined) throw new Error("the finalized transaction carries no identifier");
      // `facade.validateTransaction` is deliberately NOT called first, though the SDK
      // recommends it at this call site: it checks against a BLANK ledger state carrying
      // only the block's parameters, so it fails every contract call as a call to a
      // non-existent contract. It is a wallet-shaped check and this is not a wallet-shaped
      // transaction.
      try {
        const landed = await facade.submissionService.submitTransaction(tx, "Finalized");
        return { txId, blockHash: landed.blockHash.replace(/^0x/, "") };
      } catch (error) {
        // Undoes the optimistic spend, so the next balance does not skip a coin this
        // submit never took.
        await facade.revert(tx);
        throw error;
      }
    },
    close: () => facade.stop(),
  };
}

export async function openFundingWallet(networkId: string, endpoints: Endpoints): Promise<FundingWallet> {
  return openFacade(deriveFundingKeys(fundingSeed(), networkId), nodeConfig(networkId, endpoints));
}
