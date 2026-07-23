/**
 * The funding (gas) wallet: a seed, the three role keys derived from it, a
 * started `WalletFacade`, and the two midnight-js provider interfaces the write
 * path balances and submits through.
 *
 * THIS MODULE IS THE SERVICE'S ONLY INDEXER DEPENDENCY, and it is deliberate
 * rather than incidental. Everything else on the write path (contract state,
 * zswap chain state, ledger parameters) comes from the node's runtime API, and
 * the read seams touch no indexer at all. Balancing is different: the shielded,
 * unshielded and dust sub-wallets discover their UTXOs exclusively through
 * `indexerClientConnection`, and NO node RPC or runtime API returns UTXO or
 * dust state for an address (established by enumerating every runtime-API
 * namespace this chain exposes: `midnightRuntimeApi`, `c2mBridgeApi`,
 * `tokenBridgeIDPRuntimeApi`, `systemParametersApi`). Point the facade at a
 * dead port with node RPC intact and it loops on `Wallet.Sync` forever: there
 * is no coin selection, no dust, and therefore no fee payment.
 *
 * What that dependency does and does not cost: the indexer feeds fee payment
 * only. It is downstream of every security decision, absent from the discovery
 * pipeline, and cannot influence a response's content. A hostile indexer can
 * cause silence (withheld or stale UTXOs stop balancing; fabricated ones are
 * rejected by the node, which validates against real state) and it learns which
 * addresses this wallet uses. It can never induce a spend, because spending
 * needs the wallet keys it never sees. Self-hosting removes the disclosure;
 * reading from several endpoints removes the single point of silence.
 *
 * Nothing here touches disk: transaction history is in-memory, and the escape-
 * hatch call route in `respond.ts` constructs no private-state provider at all,
 * so the service runs from a read-only filesystem.
 */

import type * as ledger from "@midnightntwrk/ledger-v9";
import { deriveAccountKeys, initialiseWalletFacade, type AccountKeys } from "@sig-net/midnight-contract-deploy";

import type { Config } from "./config.js";

/**
 * The live key material for the funding account. Held for the process's
 * lifetime: every balance and every signature needs it.
 */
export type FundingKeys = AccountKeys;

/**
 * A started funding wallet, reduced to exactly what the write path uses.
 *
 * Deliberately NOT midnight-js's `WalletProvider & MidnightProvider`: those
 * interfaces exist to be handed to `findDeployedContract`, and this service
 * calls `createUnprovenCallTxFromInitialStates` instead, which takes no
 * provider set. The four members below are the whole surface a write needs.
 */
export interface FundingWallet {
  /** Zswap coin public key, one of the four data dependencies of a call. */
  readonly coinPublicKey: ledger.CoinPublicKey;
  /** Zswap encryption public key, passed to the unproven-call builder. */
  readonly encryptionPublicKey: ledger.EncPublicKey;
  /**
   * Balance a proven transaction: add the dust and unshielded inputs that pay
   * the fee, sign those segments, then finalize (which proves the balancing
   * segments through the configured proof server).
   */
  balance(tx: ledger.Transaction<ledger.SignatureEnabled, ledger.Proof, ledger.PreBinding>): Promise<ledger.FinalizedTransaction>;
  /** Submit and wait for the node to report the transaction finalized. */
  submit(tx: ledger.FinalizedTransaction): Promise<string>;
  /** Stop syncing and release the indexer connections. */
  close(): Promise<void>;
}

/** Balancing recipes expire this far out. Ample for a prove-and-submit round. */
const RECIPE_TTL_MS = 30 * 60 * 1000;

/**
 * Parse a funding seed: 16 to 64 bytes of hex, `0x` optional.
 *
 * Hex only, matching the Rust implementation's `MIDNIGHT_PUB_FUNDING_SEED`
 * (which was handed straight to the toolkit's `--funding-seed`), so a
 * deployment moves without touching the variable. A mnemonic is rejected here
 * rather than silently hashed into a different wallet. That rejection is also
 * the only thing keeping {@link deriveFundingKeys} narrow, since the library
 * derivation it delegates to accepts one.
 *
 * @param seed - The configured seed.
 * @returns The seed bytes.
 * @throws If the value is not 16 to 64 bytes of hex. The message never quotes
 *   the value, since this is the one true secret the service holds.
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

/**
 * Derive the three role keys (Zswap, NightExternal, Dust) from the funding
 * seed. Pure crypto: no network, and the HD wallet is cleared immediately after
 * derivation so the master key does not linger.
 *
 * @param seed - The funding seed, hex.
 * @param networkId - The network the unshielded keystore encodes addresses for.
 * @returns The derived key material.
 * @throws If the seed is malformed or key derivation is out of bounds.
 */
export function deriveFundingKeys(seed: string, networkId: string): FundingKeys {
  // NOT a redundant parse. `deriveAccountKeys` reads the seed through the
  // package's `parseSeed`, which ALSO accepts a BIP-39 mnemonic and runs it
  // through PBKDF2 into a different, unfunded wallet (measured: the same input
  // yields two different unshielded addresses). Nothing can be injected into
  // that parser, so this pre-check is the only thing holding the accepted input
  // for the one secret this service holds to what the Rust implementation took.
  // A widened seed fails much later, as `Wallet.InsufficientFunds: could not
  // balance dust`. Do not remove it.
  parseFundingSeed(seed);
  return deriveAccountKeys(seed, networkId);
}

/**
 * Open and sync the funding wallet.
 *
 * Blocks until the facade reports a synced state, because an unsynced wallet
 * has no coins to select and every balance would fail with the misleading
 * `Wallet.InsufficientFunds: could not balance dust`.
 *
 * @param config - Validated configuration; supplies both the indexer endpoints
 *   and the funding seed.
 * @returns The started wallet.
 * @throws If the seed is malformed, or the facade cannot reach the indexer,
 *   the node, or the proof server.
 */
export async function openFundingWallet(config: Config): Promise<FundingWallet> {
  const keys = deriveFundingKeys(config.fundingSeed, config.networkId);

  // Constructs the three sub-wallets and nothing more; every connection opens
  // on `start()`. `Config` satisfies the published `MidnightNodeConfig` as-is,
  // and the wiring it hides was diffed against what this file used to spell
  // out: identical fee settings (`additionalFeeOverhead` 300_000_000_000,
  // `feeBlocksMargin` 5, a smaller margin risks an underpriced transaction as
  // fees drift), the same http->ws rescue on `nodeUrl` for a facade that only
  // speaks WebSocket, and the same in-memory transaction history, which is what
  // keeps this service off a writable volume and out of an exclusive database
  // handle. The dependency is pinned to an exact version so those values cannot
  // move under it. The indexer connection it takes from `config` is this
  // service's sole indexer dependency; see this module's header.
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
