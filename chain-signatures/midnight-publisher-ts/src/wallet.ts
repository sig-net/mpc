/**
 * The funding (gas) wallet: seed, derived role keys, a started `WalletFacade`.
 *
 * THE SERVICE'S ONLY INDEXER DEPENDENCY, and unavoidable. The shielded,
 * unshielded and dust sub-wallets discover their UTXOs exclusively through
 * `indexerClientConnection`, and no node RPC or runtime API returns UTXO or dust
 * state for an address (checked against every namespace this chain exposes).
 * Point the facade at a dead indexer with node RPC intact and it loops on
 * `Wallet.Sync` forever: no coin selection, no dust, no fee payment.
 *
 * It feeds fee payment only, so it is downstream of every security decision and
 * cannot influence a response's content; see the decision record §2.5 for what a
 * hostile indexer can and cannot do. Nothing here touches disk.
 */

import type * as ledger from "@midnightntwrk/ledger-v9";
import { deriveAccountKeys, initialiseWalletFacade, type AccountKeys } from "@sig-net/midnight-contract-deploy";

import type { Config } from "./config.js";

export type FundingKeys = AccountKeys;

/**
 * Deliberately not midnight-js's `WalletProvider & MidnightProvider`: those
 * exist to be handed to `findDeployedContract`, and this service calls
 * `createUnprovenCallTxFromInitialStates`, which takes no provider set.
 */
export interface FundingWallet {
  readonly coinPublicKey: ledger.CoinPublicKey;
  readonly encryptionPublicKey: ledger.EncPublicKey;
  /** Add the dust and unshielded inputs that pay the fee, sign them, finalize. */
  balance(tx: ledger.Transaction<ledger.SignatureEnabled, ledger.Proof, ledger.PreBinding>): Promise<ledger.FinalizedTransaction>;
  /** Submit and wait for the node to report the transaction finalized. */
  submit(tx: ledger.FinalizedTransaction): Promise<string>;
  close(): Promise<void>;
}

/**
 * Ample for a prove-and-submit round, which measures ~20 s. But this value is
 * ALSO the dust-spending intent's TTL (`dust-wallet`'s `Intent.new(ttl)`), so it
 * is how long an abandoned finalize holds the fee coin: a post that dies between
 * finalize and submit strands it for up to 30 minutes, against the ~35 s the
 * concurrency design budgets. Lowering it to a few minutes would bound that;
 * left here deliberately for now, and recorded in the decision record §7.3.
 */
const RECIPE_TTL_MS = 30 * 60 * 1000;

/**
 * 16 to 64 bytes of hex, `0x` optional, matching the Rust implementation's
 * `MIDNIGHT_PUB_FUNDING_SEED` so a deployment moves without touching it. The
 * message never quotes the value.
 */
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

/** Zswap, NightExternal and Dust role keys. Pure crypto, no network. */
export function deriveFundingKeys(seed: string, networkId: string): FundingKeys {
  // NOT a redundant parse, do not remove. `deriveAccountKeys` reads the seed
  // through a parser that ALSO accepts a BIP-39 mnemonic and PBKDF2s it into a
  // different, unfunded wallet (measured: same input, two different unshielded
  // addresses). A widened seed then fails much later as
  // `Wallet.InsufficientFunds: could not balance dust`.
  parseFundingSeed(seed);
  return deriveAccountKeys(seed, networkId);
}

/** Opens and blocks until synced: an unsynced wallet fails every balance. */
export async function openFundingWallet(config: Config): Promise<FundingWallet> {
  const keys = deriveFundingKeys(config.fundingSeed, config.networkId);

  // Constructs the sub-wallets only; connections open on `start()`. The wiring
  // it hides was diffed against what this file used to spell out and is
  // identical (fee overhead and block margin, the http->ws rescue for a facade
  // that only speaks WebSocket, in-memory transaction history, which is what
  // keeps this service off a writable volume). Pinned to an exact version so
  // those values cannot move under it.
  const facade = await initialiseWalletFacade(keys, config);

  await facade.start(keys.shieldedSecretKeys, keys.dustSecretKey);
  await facade.waitForSyncedState();

  return {
    coinPublicKey: keys.shieldedSecretKeys.coinPublicKey,
    encryptionPublicKey: keys.shieldedSecretKeys.encryptionPublicKey,
    async balance(tx) {
      const recipe = await facade.balanceUnboundTransaction(
        tx,
        { shieldedSecretKeys: keys.shieldedSecretKeys, dustSecretKey: keys.dustSecretKey },
        { ttl: new Date(Date.now() + RECIPE_TTL_MS) },
      );
      const signed = await facade.signRecipe(recipe, keys.unshieldedKeystore.signDataAsync);
      return facade.finalizeRecipe(signed);
    },
    submit: (tx) => facade.submitTransaction(tx),
    close: async () => {
      await facade.stop();
    },
  };
}
