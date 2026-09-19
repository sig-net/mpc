// Adapts the WalletFacade-based account to midnight-js's wallet interfaces,
// so midnight-js (`findDeployedContract` → `contract.callTx.<circuit>(...)`)
// can balance, prove and submit contract-call transactions through the same
// wallet this package builds. compact-js binds contracts and runs circuits
// locally but does NOT assemble + prove + submit a ledger call transaction —
// midnight-js is the orchestration layer for that. The contract-specific
// provider set (indexer / proof server / zk-config / private-state store)
// lives with each contract package, since it depends on that package's
// compiled assets.
import {
  createProofProvider,
  type MidnightProvider,
  type ProofProvider,
  type UnboundTransaction,
  type WalletProvider,
  type ZKConfigProvider,
  ZKConfigRegistry,
  zkConfigToProvingKeyMaterial,
} from "@midnight-ntwrk/midnight-js/types";
import { httpClientProvingProvider } from "@midnight-ntwrk/midnight-js-http-client-proof-provider";
import type { ProvingKeyMaterial, ProvingProvider } from "@midnightntwrk/ledger-v9";
import { ContractCall } from "@midnightntwrk/ledger-v9";
import type { AccountKeys, NetworkId, WalletFacade } from "@sig-net/midnight-contract-deploy";

import { withOperationProgress } from "./operation-progress.ts";
import { ensureTransactionFee } from "./transaction-fees.ts";

// Balancing recipes expire 30 min out (same TTL as submitUnprovenTransaction).
const BALANCE_TTL_MS = 30 * 60 * 1000;

/**
 * Adapt a started {@link WalletFacade} + {@link AccountKeys} to midnight-js's
 * `WalletProvider & MidnightProvider`. `balanceTx` balances the unbound
 * transaction with the account's shielded/dust keys, signs, then finalizes
 * (which proves); `submitTx` relays through the facade.
 *
 * The midnight-js ledger types come from `midnight-js-protocol`; the facade
 * uses `ledger-v9`. They are the same underlying classes, so the values pass
 * straight through — the casts only bridge the two packages' nominal type
 * identities.
 *
 * @param facade - A started (and synced) wallet facade.
 * @param keys - The key material of the same wallet, for balancing and signing.
 * @param networkId - The network used for wallet funding addresses.
 * @returns The provider pair midnight-js uses as balancer + submitter.
 */
export function createWalletAndMidnightProvider(
  facade: WalletFacade,
  keys: AccountKeys,
  networkId: NetworkId,
): WalletProvider & MidnightProvider {
  return {
    getCoinPublicKey: () => keys.shieldedSecretKeys.coinPublicKey,
    getEncryptionPublicKey: () => keys.shieldedSecretKeys.encryptionPublicKey,
    async balanceTx(tx: UnboundTransaction, ttl?: Date) {
      const intents = [...(tx.intents?.values() ?? [])];
      const expires: number = Math.min(
        ttl?.getTime() ?? Date.now() + BALANCE_TTL_MS,
        ...intents.map((intent) => intent.ttl.getTime()),
      );
      const deadline: number = expires - 60_000;
      const calls: string = intents
        .flatMap((intent) => intent.actions)
        .filter((action) => action instanceof ContractCall)
        .map(
          (action) =>
            `${action.address}/${typeof action.entryPoint === "string" ? action.entryPoint : new TextDecoder().decode(action.entryPoint)}`,
        )
        .join(", ");
      const label = `Midnight ${calls || "transaction"}`;
      await ensureTransactionFee(facade, keys, networkId, tx, expires, label);
      const recipe = await withOperationProgress(
        `${label} balancing`,
        () =>
          facade.balanceUnboundTransaction(
            tx,
            { shieldedSecretKeys: keys.shieldedSecretKeys, dustSecretKey: keys.dustSecretKey },
            { ttl: new Date(expires) },
          ),
        deadline,
      );
      const signed = await facade.signRecipe(recipe, keys.unshieldedKeystore.signDataAsync);
      return await withOperationProgress(
        `${label} finalisation`,
        () => facade.finalizeRecipe(signed),
        expires,
      );
    },
    async submitTx(tx) {
      return await withOperationProgress("Midnight submission", async () => {
        const id = await facade.submitTransaction(tx);
        console.log(`Midnight submitted transaction: ${id}`);
        return id;
      });
    },
  };
}

/** Phase of one proof-server round trip reported to a {@link ProofServerObserver}. */
export enum ProofServerPhase {
  Check = "check",
  Prove = "prove",
}

/**
 * One observed proof-server round trip (a /check or /prove call), as reported
 * to a {@link ProofServerObserver}. `keyLocation` attributes the round trip to
 * a circuit: `contract:<addr>/<circuitId>?vk=…` for contract circuits,
 * `midnight/...` for protocol builtins.
 */
export interface ProofServerObservation {
  /** Which endpoint the round trip hit. */
  readonly phase: ProofServerPhase;
  /** Canonical proving key location of the call being checked/proved. */
  readonly keyLocation: string;
  /** Wall-clock duration of the round trip. */
  readonly ms: number;
  /** The serialized proof preimage sent to the proof server. */
  readonly serializedPreimage: Uint8Array;
  /** The proof returned by /prove (successful {@link ProofServerPhase.Prove} observations only). */
  readonly proof?: Uint8Array;
  /**
   * Error message when the round trip threw. The observer sees it before any retry, so a
   * connection-level failure recorded here can still succeed on a later attempt and never
   * reach the caller.
   */
  readonly error?: string;
}

/**
 * Sink for {@link ProofServerObservation}s, called synchronously after each
 * /check and /prove round trip of a provider built with
 * {@link createCrossContractProofServerProvider}. Must not throw.
 */
export type ProofServerObserver = (observation: ProofServerObservation) => void;

// A proof server that dies mid-run refuses the next connection. midnight-js's own retry covers
// only HTTP 500/503, so a refused connection rejects at once and fails a flow that is minutes in.
// Retry the connection-level failures. They are transient by definition, and a request that never
// reached the server cannot have been applied, so a retry is safe.
const CONNECTION_ERROR = /ECONNREFUSED|ECONNRESET|EPIPE|socket hang up|fetch failed|network error/i;
const PROOF_ATTEMPTS = 3;
const PROOF_RETRY_DELAY_MS = 5_000;

/**
 * Run a proof-server call, retrying it when the connection itself fails.
 *
 * @param what - The call being made ("check" or "prove"), for the warning line.
 * @param call - The call to run.
 * @returns The call's result.
 * @throws {Error} The last error when the attempts run out, or immediately for any non-connection error.
 */
async function withConnectionRetry<T>(what: string, call: () => Promise<T>): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await call();
    } catch (error) {
      const cause =
        error instanceof Error && error.cause instanceof Error ? error.cause.message : "";
      const message = error instanceof Error ? `${error.message} ${cause}` : String(error);
      if (attempt >= PROOF_ATTEMPTS || !CONNECTION_ERROR.test(message)) throw error;
      console.warn(
        `proof server ${what}: connection lost on attempt ${String(attempt)}, retrying. ${message}`,
      );
      await new Promise((resolve) => setTimeout(resolve, PROOF_RETRY_DELAY_MS * attempt));
    }
  }
}

/**
 * Build the {@link ProofProvider} for a contract's provider set: proving via
 * the proof server's /check + /prove endpoints, with proving/verifier keys
 * resolved across a *set* of compiled-contract sources — what a
 * **cross-contract call** needs: one transaction whose call tree spans several
 * deployed contracts, each carrying its own proof, so proving must find
 * artifacts for every contract in the tree (the root and each callee). A
 * single-contract provider set is just the one-element case.
 *
 * The `ZKConfigRegistry` joins each call's canonical key location
 * (`contract:<addr>/<circuitId>?vk=<sha-256 of the deployed verifier key>`) to
 * the source whose local verifier key matches — immune to redeploys and to
 * circuit-name collisions across contracts. Pass one `ZKConfigProvider` per
 * compiled contract the call can reach (the caller plus every callee).
 *
 * Exists instead of midnight-js's own `httpClientProofProvider` because that
 * one (5.0.0-beta.3) builds a circuit-level `ProvingProvider` with only
 * `check`/`prove` — the ledger-v9 1.0.0-rc.2 shape it was released against —
 * while the ledger-v9 1.0.0-rc.3 WASM this workspace resolves (the version
 * the wallet-sdk betas pin) validates that `lookupKey` is also present and
 * throws "expected proving provider property 'lookupKey' to be a function"
 * on every circuit-call proof. This wrapper reuses midnight-js's proving
 * provider and grafts on a `lookupKey` backed by the same key-material
 * resolution its `check`/`prove` use. Delete in favor of
 * `httpClientProofProvider` once midnight-js ships a beta aligned with
 * ledger-v9 1.0.0-rc.3.
 *
 * @param proofServerUrl - The proof server's HTTP endpoint.
 * @param zkConfigProviders - One provider per compiled contract in the call tree; must be non-empty.
 * @param observer - Called after every /check and /prove HTTP round trip, one call per attempt: a retried connection failure yields one errored observation per failed attempt plus one for the success, and retry backoff never counts into an observation's `ms`.
 * @returns The proof provider to place in a contract's midnight-js provider set.
 * @throws {Error} If `zkConfigProviders` is empty.
 */
export function createCrossContractProofServerProvider(
  proofServerUrl: string,
  zkConfigProviders: readonly ZKConfigProvider<string>[],
  observer?: ProofServerObserver,
): ProofProvider {
  if (zkConfigProviders.length === 0) {
    throw new Error(
      "createCrossContractProofServerProvider: at least one zkConfigProvider is required",
    );
  }

  const registry = new ZKConfigRegistry([...zkConfigProviders]);

  // Pass the REGISTRY (not a single provider) to the base: its /check and
  // /prove key resolution (`makeKeyMaterialResolver`) special-cases a
  // ZKConfigRegistry and resolves every contract in the call tree through it.
  // Passing one provider would leave /check unable to find a *callee* circuit's
  // key (its verifier-key join has only the caller), which fails a
  // cross-contract call at the check step. The `as` bridges the nominal type:
  // the base only ever calls `.resolveKeyLocation` on a registry argument.
  // The timeout raises midnight-js's 5-minute default: a cross-contract prove
  // takes minutes even unloaded, and on a busy host the default aborts proves
  // that would have completed ("'prove' returned an error: AbortError").
  const base = httpClientProvingProvider(
    proofServerUrl,
    registry as unknown as ZKConfigProvider<string>,
    { timeout: 15 * 60 * 1000 },
  );

  // Same resolution order as midnight-js's internal key-material resolver:
  // canonical contract key locations through the registry's verifier-key
  // join; otherwise try the location as a bare circuit name against each flat
  // provider in turn; protocol builtins ("midnight/...") resolve to undefined
  // and are supplied by the proof server itself.
  const lookupKey = async (keyLocation: string): Promise<ProvingKeyMaterial | undefined> => {
    const resolved = await registry.resolveKeyLocation(keyLocation);
    if (resolved !== undefined) {
      return zkConfigToProvingKeyMaterial(resolved);
    }
    for (const provider of zkConfigProviders) {
      try {
        return zkConfigToProvingKeyMaterial(await provider.get(keyLocation));
      } catch {
        // try the next provider
      }
    }
    return undefined;
  };

  // The observer sits INSIDE the connection retry, wrapping the base HTTP client
  // directly: each attempt is one observation with its own ms and (on failure) its
  // own error, so retry backoff sleeps never inflate a recorded round trip and
  // failed attempts are visible even when a later attempt succeeds.
  const observed: Pick<ProvingProvider, "check" | "prove"> =
    observer === undefined
      ? base
      : {
          async check(serializedPreimage, keyLocation) {
            const start = performance.now();
            try {
              const result = await base.check(serializedPreimage, keyLocation);
              observer({
                phase: ProofServerPhase.Check,
                keyLocation,
                serializedPreimage,
                ms: performance.now() - start,
              });
              return result;
            } catch (error) {
              observer({
                phase: ProofServerPhase.Check,
                keyLocation,
                serializedPreimage,
                ms: performance.now() - start,
                error: String(error),
              });
              throw error;
            }
          },
          async prove(serializedPreimage, keyLocation, overwriteBindingInput) {
            const start = performance.now();
            try {
              const proof = await base.prove(
                serializedPreimage,
                keyLocation,
                overwriteBindingInput,
              );
              observer({
                phase: ProofServerPhase.Prove,
                keyLocation,
                serializedPreimage,
                proof,
                ms: performance.now() - start,
              });
              return proof;
            } catch (error) {
              observer({
                phase: ProofServerPhase.Prove,
                keyLocation,
                serializedPreimage,
                ms: performance.now() - start,
                error: String(error),
              });
              throw error;
            }
          },
        };

  const provingProvider: ProvingProvider = {
    ...base,
    lookupKey,
    check: (serializedPreimage, keyLocation) =>
      withOperationProgress(`proof check ${keyLocation}`, () =>
        withConnectionRetry("check", () => observed.check(serializedPreimage, keyLocation)),
      ),
    prove: (serializedPreimage, keyLocation, overwriteBindingInput) =>
      withOperationProgress(`proof prove ${keyLocation}`, () =>
        withConnectionRetry("prove", () =>
          observed.prove(serializedPreimage, keyLocation, overwriteBindingInput),
        ),
      ),
  };
  return createProofProvider(provingProvider);
}
