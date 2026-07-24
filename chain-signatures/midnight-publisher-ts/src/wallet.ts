/**
 * The funding (gas) wallet.
 *
 * THE SERVICE'S ONLY INDEXER DEPENDENCY, and unavoidable: the sub-wallets
 * discover their UTXOs exclusively through the indexer, and no node RPC returns
 * UTXO or dust state for an address. It feeds fee payment only, so it sits
 * downstream of every security decision. Nothing here touches disk.
 */

import type { MidnightProvider, WalletProvider } from "@midnight-ntwrk/midnight-js-types";
import { deriveAccountKeys, initialiseWalletFacade, type AccountKeys } from "@sig-net/midnight-contract-deploy";

import type { Config } from "./config.js";

/**
 * `balanceTx` adds the dust and unshielded inputs that pay the fee, signs them
 * and finalizes. `submitTx` waits for the node to report finality.
 */
export interface FundingWallet extends WalletProvider, MidnightProvider {
  close(): Promise<void>;
}

/**
 * Ample for a prove-and-submit round, which measures ~20 s. But this value is
 * ALSO the dust-spending intent's TTL (`dust-wallet`'s `Intent.new(ttl)`), so it
 * is how long an abandoned finalize holds the fee coin: a post that dies between
 * finalize and submit strands it for up to this long, which is why `respond.ts`
 * puts no deadline past the balance stage. Five minutes is ~15x the measured
 * round and bounds the stranded window (decision record §7.3; was 30 minutes).
 */
const RECIPE_TTL_MS = 5 * 60 * 1000;

/** Hex only, 16 to 64 bytes. The message never quotes the value. */
export function parseFundingSeed(seed: string): Uint8Array {
  const compact = seed.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]+$/.test(compact) || compact.length % 2 !== 0) {
    throw new Error("MIDNIGHT_PUB_FUNDING_SEED must be hex (16 to 64 bytes); a mnemonic is not accepted");
  }
  const bytes = compact.length / 2;
  if (bytes < 16 || bytes > 64) {
    throw new Error(`MIDNIGHT_PUB_FUNDING_SEED must be 16 to 64 bytes of hex, got ${bytes}`);
  }
  return Uint8Array.from(Buffer.from(compact, "hex"));
}

export function deriveFundingKeys(seed: string, networkId: string): AccountKeys {
  // Not redundant: `deriveAccountKeys` also accepts a BIP-39 mnemonic and
  // PBKDF2s it into a different, unfunded wallet.
  parseFundingSeed(seed);
  return deriveAccountKeys(seed, networkId);
}

/** Opens and blocks until synced: an unsynced wallet fails every balance. */
export async function openFundingWallet(config: Config): Promise<FundingWallet> {
  const keys = deriveFundingKeys(config.fundingSeed, config.networkId);

  const facade = await initialiseWalletFacade(keys, config);

  await facade.start(keys.shieldedSecretKeys, keys.dustSecretKey);
  await facade.waitForSyncedState();

  return {
    getCoinPublicKey: () => keys.shieldedSecretKeys.coinPublicKey,
    getEncryptionPublicKey: () => keys.shieldedSecretKeys.encryptionPublicKey,
    // The interface allows a `ttl`; honour it rather than silently dropping it.
    async balanceTx(tx, ttl) {
      const secretKeys = { shieldedSecretKeys: keys.shieldedSecretKeys, dustSecretKey: keys.dustSecretKey };
      const recipe = await facade.balanceUnboundTransaction(tx, secretKeys, {
        ttl: ttl ?? new Date(Date.now() + RECIPE_TTL_MS),
      });
      const signed = await facade.signRecipe(recipe, keys.unshieldedKeystore.signDataAsync);
      return facade.finalizeRecipe(signed);
    },
    submitTx: (tx) => facade.submitTransaction(tx),
    close: () => facade.stop(),
  };
}
