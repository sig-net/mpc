// Per-flow-file wallet + reader lifecycle — the GENERIC half of an example's
// e2e session. Each flow test file creates ONE session at module scope, uses
// it lazily from its tests, and stops it in afterAll. Files run in separate
// workers (the example's vitest config serializes them), so a session never
// crosses files — the lazy construction keeps the offline path
// (RUN_INTEGRATION_TESTS unset) from ever touching the network. Everything
// contract-specific (providers, joined contract handles, identity) is the
// example's: it wraps {@link E2eSession.wallet} to build its own context.
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import {
  signetEventSourceFromPublicDataProvider,
  SignetRequestResponseReader,
} from "@sig-net/midnight";
import {
  type AccountKeys,
  deriveAccountKeys,
  getMidnightNodeConfig,
  initialiseWalletFacade,
  type WalletFacade,
} from "@sig-net/midnight-contract-deploy";
import { withOperationProgress } from "../lib/operation-progress.ts";

import { requireEnv } from "./e2e-env.ts";

/**
 * The user-side wallet seed in effect: `USER_SEED`, a role wallet the setup
 * resolves (generated + persisted to `.env` when absent) and funds from the
 * root wallet — see wallets.ts. Required: by the time a session or identity
 * derivation runs, the wallet steps have populated it.
 *
 * @param env - The environment to read `USER_SEED` from.
 * @returns The seed (hex or mnemonic) the user-side flows spend from.
 * @throws {Error} If `USER_SEED` is unset (the wallet steps did not run).
 */
export function resolveUserSeed(env: NodeJS.ProcessEnv): string {
  return requireEnv(env, "USER_SEED");
}

/** The started user wallet a session hands out: facade + its key material. */
export interface SessionWallet {
  /** A started (and synced) wallet facade — pays for and submits transactions. */
  readonly facade: WalletFacade;
  /** The key material of the same wallet, for balancing and signing. */
  readonly keys: AccountKeys;
}

/** The shared per-flow-file lifecycle handed out by {@link createE2eSession}. */
export interface E2eSession {
  /** The shared started-and-synced user wallet; built lazily on first use. */
  wallet(): Promise<SessionWallet>;
  /**
   * The shared MPC-style request/response reader for one request map, built
   * lazily and cached per path.
   *
   * @param requestsPath - Resolved ledger-tree path of the requester
   *   contract's request index, the same path the contract packs as
   *   `requestsPath` in that map's notifications (`[0]` for a flat contract's
   *   field 0, longer once the compiler chunks past 15 fields). A contract may
   *   declare several request maps, so the reader cannot assume one.
   */
  responseReader(requestsPath: readonly number[]): SignetRequestResponseReader;
  /** Stop the wallet facade (call from afterAll); safe when never started. */
  stop(): Promise<void>;
}

/** What {@link createE2eSession} reads from the env accumulator. */
export interface E2eSessionOptions {
  /** The setup-populated env accumulator (seeds, node config, contract addresses). */
  env: NodeJS.ProcessEnv;
  /**
   * Env-var name holding the example's requester contract address (the
   * contract whose signature requests the reader follows), e.g.
   * `MIDNIGHT_VAULT_CONTRACT_ADDRESS`.
   */
  requesterAddressEnvVar: string;
}

/**
 * Create the shared wallet + reader lifecycle for one flow test file.
 *
 * The wallet is built lazily on first use — it needs the setup pipeline to
 * have populated `env` — started once, and stopped once via `stop()`. Each
 * access re-awaits synced state (instant when already synced) so long tests
 * / STEP_THROUGH pauses can't hand out a stale wallet.
 *
 * A reader is likewise built lazily, one per request-map path, over the
 * example's requester contract / signet contract pair, backed by a fresh
 * indexerPublicDataProvider so it reads RAW ledger state exactly as the
 * response server does. Each caches its fetched request records, so repeated
 * lookups across tests cost one query each.
 *
 * @param options - The env accumulator and the requester-address env var.
 * @returns The session lifecycle.
 */
export function createE2eSession(options: E2eSessionOptions): E2eSession {
  const { env } = options;
  let sharedWallet: SessionWallet | undefined;
  const readersByPath = new Map<string, SignetRequestResponseReader>();

  return {
    async wallet(): Promise<SessionWallet> {
      if (!sharedWallet) {
        const config = getMidnightNodeConfig(env);
        const keys = deriveAccountKeys(resolveUserSeed(env), config.networkId);
        const facade = await initialiseWalletFacade(keys, config);
        await facade.start(keys.shieldedSecretKeys, keys.dustSecretKey);
        await withOperationProgress("user wallet synchronisation", () =>
          facade.waitForSyncedState(),
        );
        sharedWallet = { facade, keys };
      }
      const facade = sharedWallet.facade;
      await withOperationProgress("user wallet synchronisation", () => facade.waitForSyncedState());
      return sharedWallet;
    },

    responseReader(requestsPath: readonly number[]): SignetRequestResponseReader {
      const key = requestsPath.join(",");
      const cached = readersByPath.get(key);
      if (cached) {
        return cached;
      }
      const nodeConfig = getMidnightNodeConfig(env);
      const publicDataProvider = indexerPublicDataProvider({
        queryURL: nodeConfig.indexerUrl,
        subscriptionURL: nodeConfig.indexerWsUrl,
      });
      const reader = new SignetRequestResponseReader({
        requesterContractAddress: requireEnv(env, options.requesterAddressEnvVar),
        requesterRequestsPath: requestsPath,
        signetContractAddress: requireEnv(env, "MIDNIGHT_SIGNET_CONTRACT_ADDRESS"),
        publicDataProvider,
        // The MPC's responses are read from the contract events the
        // signet contract emits, through the same provider.
        eventSource: signetEventSourceFromPublicDataProvider(publicDataProvider),
      });
      readersByPath.set(key, reader);
      return reader;
    },

    async stop(): Promise<void> {
      await sharedWallet?.facade.stop().catch(() => undefined);
    },
  };
}
