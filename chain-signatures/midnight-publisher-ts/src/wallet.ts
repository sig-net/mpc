// The funding (gas) wallet, and the only reason this process talks to an indexer:
// spendable DUST is derived by replaying ledger events, which no node RPC serves.

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

// Derived rather than imported: the type's home package would be a second copy of the wallet SDK.
export type BalancingRecipe = Awaited<ReturnType<WalletFacade["signRecipe"]>>;

export interface Landed {
  readonly txId: string;
  readonly blockHash: string;
}

export interface FundingWallet {
  balanceTx(tx: UnboundTransaction, ttl?: Date): Promise<BalancingRecipe>;
  finalizeTx(recipe: BalancingRecipe): Promise<FinalizedTransaction>;
  submitTx(tx: FinalizedTransaction): Promise<Landed>;
  close(): Promise<void>;
}

// Also the dust intent's TTL: how long a submit dying between finalize and submit strands the coin.
const RECIPE_TTL_MS = 5 * 60 * 1000;

// Hex only; the message names the env var and never quotes the value.
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
  // Not redundant: `deriveAccountKeys` also accepts a BIP-39 mnemonic and PBKDF2s it
  // into a different, unfunded wallet.
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
    async balanceTx(tx, ttl) {
      const secretKeys = { shieldedSecretKeys: keys.shieldedSecretKeys, dustSecretKey: keys.dustSecretKey };
      const recipe = await facade.balanceUnboundTransaction(tx, secretKeys, {
        ttl: ttl ?? new Date(Date.now() + RECIPE_TTL_MS),
      });
      return facade.signRecipe(recipe, keys.unshieldedKeystore.signDataAsync);
    },
    finalizeTx: (recipe) => facade.finalizeRecipe(recipe),
    // The submission service, not `facade.submitTransaction`: that discards the landing
    // block, which is half of what this process owes its caller.
    async submitTx(tx) {
      const txId = tx.identifiers().at(-1);
      if (txId === undefined) throw new Error("the finalized transaction carries no identifier");
      // `facade.validateTransaction` is deliberately not called: it checks against a
      // blank ledger state and fails every contract call.
      try {
        const landed = await facade.submissionService.submitTransaction(tx, "Finalized");
        return { txId, blockHash: landed.blockHash.replace(/^0x/, "") };
      } catch (error) {
        // Undo the optimistic spend, so the next balance does not skip this coin.
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
