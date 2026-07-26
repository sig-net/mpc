/**
 * The funding (gas) wallet.
 *
 * THE SERVICE'S ONLY INDEXER DEPENDENCY, and unavoidable: the sub-wallets
 * discover their UTXOs exclusively through the indexer, and no node RPC returns
 * UTXO or dust state for an address. It feeds fee payment only, so it sits
 * downstream of every security decision. Nothing here touches disk.
 */

import type { MidnightProvider, WalletProvider } from "@midnight-ntwrk/midnight-js-types";
import {
  deriveAccountKeys,
  initialiseWalletFacade,
  parseSeed,
  SeedFormat,
  type AccountKeys,
  type MidnightNodeConfig,
} from "@sig-net/midnight-contract-deploy";

import { fundingSeed, type Config } from "./config.js";

/**
 * `balanceTx` adds the dust and unshielded inputs that pay the fee, signs them
 * and finalizes. `submitTx` waits for the node to report finality.
 */
export interface FundingWallet extends WalletProvider, MidnightProvider {
  close(): Promise<void>;
}

/**
 * Doubles as the dust-spending intent's TTL, so it is how long a post that
 * dies between finalize and submit strands the fee coin, and why `respond.ts`
 * bounds nothing past balance. ~15x the measured ~20 s round.
 */
const RECIPE_TTL_MS = 5 * 60 * 1000;

/** Hex only, via the library's own seed parser. The message names the env var and never quotes the value. */
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

/** The five fields the facade declares, not the whole `Config`. */
export function nodeConfig(config: Config): MidnightNodeConfig {
  return {
    indexerUrl: config.indexerUrl,
    indexerWsUrl: config.indexerWsUrl,
    nodeUrl: config.nodeUrl,
    proofServerUrl: config.proofServerUrl,
    networkId: config.networkId,
  };
}

async function openFacade(keys: AccountKeys, config: MidnightNodeConfig): Promise<FundingWallet> {
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

/** Opens and blocks until synced: an unsynced wallet fails every balance. */
export async function openFundingWallet(config: Config): Promise<FundingWallet> {
  return openFacade(deriveFundingKeys(fundingSeed(), config.networkId), nodeConfig(config));
}
