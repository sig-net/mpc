// Per-flow-file session: the harness's generic wallet + reader lifecycle
// wrapped with the vault's own context (providers + joined contract +
// identity). Each flow test file creates ONE session at module scope, uses
// it lazily from its tests, and stops it in afterAll — the lazy construction
// keeps the offline path (RUN_INTEGRATION_TESTS unset) from ever touching
// the network.

import type { SignetRequestResponseReader } from "@sig-net/midnight";
import type { ProofServerObservation, ProofServerObserver } from "../lib/midnight-providers.ts";
import { createE2eSession, type E2eSession, type SessionWallet } from "../test-harness/session.ts";

import { createVaultContext, type VaultContext } from "./vault-context.ts";

/** The shared per-flow-file lifecycle handed out by {@link createVaultSession}. */
export interface VaultSession {
  /** The shared wallet-backed vault context; built lazily on first use. */
  vaultContext(): Promise<VaultContext>;
  /**
   * The shared started-and-synced session wallet (facade + keys) the context
   * is built around — for flows that drive the WALLET itself (balance reads,
   * wallet-to-wallet transfers) rather than the vault contract.
   */
  wallet(): Promise<SessionWallet>;
  /**
   * The shared MPC-style request/response reader for one of the vault's
   * request maps. See the harness's `createE2eSession`.
   *
   * @param requestsPath - The map's resolved ledger-tree path, from the
   *   contract package's exported `VAULT_*_REQUESTS_PATH` constants.
   */
  responseReader(requestsPath: readonly number[]): SignetRequestResponseReader;
  /** Stop the wallet facade (call from afterAll); safe when never started. */
  stop(): Promise<void>;
}

/**
 * Create the shared session for one flow test file: the harness session's
 * lazily started-and-synced user wallet, wrapped in the vault context on
 * first use. Each `vaultContext()` access re-awaits synced wallet state
 * (instant when already synced) so long tests / STEP_THROUGH pauses can't
 * hand out a stale wallet.
 *
 * @param env - The setup-populated env accumulator.
 * @param proofObserver - Called after every proof-server /check and /prove round trip.
 * @returns The session lifecycle.
 */
export function createVaultSession(
  env: NodeJS.ProcessEnv,
  proofObserver?: ProofServerObserver,
): VaultSession {
  const session: E2eSession = createE2eSession({
    env,
    requesterAddressEnvVar: "MIDNIGHT_VAULT_CONTRACT_ADDRESS",
  });
  let sharedContext: VaultContext | undefined;

  return {
    async vaultContext(): Promise<VaultContext> {
      // wallet() re-awaits synced state on every call; the context itself is
      // built once (findDeployedContract needs the setup-deployed vault).
      const wallet = await session.wallet();
      sharedContext ??= await createVaultContext(
        env,
        wallet,
        (observation: ProofServerObservation): void => {
          console.log(
            `proof ${observation.phase} ${observation.keyLocation}: ${(observation.ms / 1000).toFixed(2)}s, ${observation.error === undefined ? "completed" : `failed: ${observation.error}`}`,
          );
          proofObserver?.(observation);
        },
      );
      return sharedContext;
    },

    wallet(): Promise<SessionWallet> {
      return session.wallet();
    },

    responseReader(requestsPath: readonly number[]): SignetRequestResponseReader {
      return session.responseReader(requestsPath);
    },

    async stop(): Promise<void> {
      await session.stop();
    },
  };
}
