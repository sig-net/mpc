// The split-deploy plumbing the deploy SDK does not offer, shared by every
// example whose verifier-key set overflows a block: building the unproven base
// deploy that registers only some circuits, and the maintenance-update
// transactions that install the rest. Everything contract-SPECIFIC
// (constructor args, witness implementations, initial private state) stays in
// the example's own deploy package and arrives here through the type
// parameters. Configuration is read from the `env` map passed in, never from
// `process.env`, so one caller can deploy under an environment it composed.

import { NodeContext } from "@effect/platform-node";
import type { Contract } from "@midnight-ntwrk/compact-js/effect";
import { CompiledContract, ContractExecutable } from "@midnight-ntwrk/compact-js/effect";
import { ZKFileConfiguration } from "@midnight-ntwrk/compact-js-node/effect";
import * as CoinPublicKey from "@midnight-ntwrk/platform-js/effect/CoinPublicKey";
import * as Configuration from "@midnight-ntwrk/platform-js/effect/Configuration";
import * as SigningKey from "@midnight-ntwrk/platform-js/effect/SigningKey";
import * as ledger from "@midnightntwrk/ledger-v9";
import {
  type DeployTransaction,
  envOrUndefined,
  type NetworkId,
} from "@sig-net/midnight-contract-deploy";
import { Effect, Layer, Option } from "effect";

// How long the deploy intent stays valid before it must be re-built.
const DEPLOY_TTL_MS = 30 * 60 * 1000;

// `MAINTENANCE_SIGNING_KEY` normalized to bare lowercase hex, or undefined when
// unset. Shared by every reader so the accepted spellings cannot drift apart.
function maintenanceSigningKeyHex(env: Record<string, string | undefined>): string | undefined {
  const raw = envOrUndefined(env, "MAINTENANCE_SIGNING_KEY");
  if (!raw) return undefined;
  const hex = raw.trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error(
      "MAINTENANCE_SIGNING_KEY must be 32 bytes of hex (0x optional): a BIP-340 signing key.",
    );
  }
  return hex;
}

/** A circuit held back from the base deploy, added afterwards by a maintenance update. */
export interface DeferredCircuit {
  /** The provable circuit id (its name). */
  readonly circuitId: string;
  /** The circuit's verifier key bytes, carried to the maintenance-add. */
  readonly verifierKey: Uint8Array;
}

/** A base deploy plus the circuits split out for follow-up maintenance updates. */
export interface SplitDeployTransaction extends DeployTransaction {
  /** The deferred circuits, in deploy order, to add via {@link buildMaintenanceInsertTransaction}. */
  readonly deferred: readonly DeferredCircuit[];
}

const operationIdToString = (id: string | Uint8Array): string =>
  typeof id === "string" ? id : new TextDecoder().decode(id);

/**
 * Thrown by a split-deploy flow that fails AFTER its base deploy transaction
 * was submitted, so the caller knows a contract is live and a rerun from the
 * top would deploy a second one: recovery is the example's resume entrypoint
 * against the live address, never a retry of the flow.
 */
export class SplitDeployAfterBaseSubmitError extends Error {}

/**
 * The circuit ids a live contract state carries operations for: the base
 * deploy's circuits plus every maintenance add that landed, so a resume can
 * tell which deferred circuits are still missing.
 *
 * @param contractStateBytes - Serialized live contract state (from queryContractState).
 * @returns The installed circuit ids, in the ledger's order.
 */
export function installedCircuitIds(contractStateBytes: Uint8Array): string[] {
  const state = ledger.ContractState.deserialize(contractStateBytes);
  return [...state.operations()].map(operationIdToString);
}

/**
 * Build an UNPROVEN contract-deploy transaction (run the Compact constructor,
 * attach the verifier keys, wrap the state in a deploy intent) that registers
 * ONLY the circuits in `baseCircuitIds` in the initial contract state,
 * returning the REST so the caller can add them with
 * {@link buildMaintenanceInsertTransaction}. A contract whose full
 * verifier-key set overflows a block (the 17-circuit vault) deploys as a small base
 * plus per-circuit maintenance adds. Keep `baseCircuitIds` minimal (one small circuit
 * is enough) so the base tx is well under the block limit; every other circuit is
 * deferred. The constructor runs once over the full assets (every key must be present);
 * the split is purely which operations land in the deployed state. Requires
 * `MAINTENANCE_SIGNING_KEY` so the contract has an authority to sign the follow-up adds.
 *
 * @param compiledContract - The bound contract, from the deploy SDK's `makeCompiledContract`.
 * @param networkId - The network the transaction targets.
 * @param coinPublicKeyHex - The deploying wallet's Zswap coin public key (hex).
 * @param env - The environment carrying `MAINTENANCE_SIGNING_KEY` (see {@link resolveMaintenanceSigningKey}).
 * @param initialPrivateState - The private state the constructor runs against.
 * @param baseCircuitIds - Circuit ids to register in the base deploy; all others are deferred.
 * @param constructorArgs - The contract's constructor arguments.
 * @returns The base {@link DeployTransaction} plus the {@link DeferredCircuit}s to add next.
 * @throws {Error} If `MAINTENANCE_SIGNING_KEY` is unset (the deferred circuits could never be
 *   installed), a `baseCircuitIds` entry matches no compiled circuit, the constructor traps,
 *   or a verifier key is missing (run `npm run compile`).
 */
export async function buildDeployTransactionDeferring<C extends Contract.Contract<PS>, PS>(
  compiledContract: CompiledContract.CompiledContract<C, PS>,
  networkId: NetworkId,
  coinPublicKeyHex: string,
  env: Record<string, string | undefined>,
  initialPrivateState: PS,
  baseCircuitIds: readonly string[],
  ...constructorArgs: Contract.Contract.InitializeParameters<C>
): Promise<SplitDeployTransaction> {
  // Fail before anything is built, let alone submitted: without an authority key the
  // base deploy would land under an SDK-sampled throwaway authority and the deferred
  // circuits could never be installed, leaving a permanently unusable contract.
  if (Option.isNone(resolveMaintenanceSigningKey(env))) {
    throw new Error(
      "MAINTENANCE_SIGNING_KEY must be set for a split deploy: the deferred circuits are " +
        "installed by maintenance updates its authority signs.",
    );
  }
  const keysLayer = Layer.succeed(Configuration.Keys, {
    coinPublicKey: CoinPublicKey.Hex(coinPublicKeyHex),
    getSigningKey: () => resolveMaintenanceSigningKey(env),
  });

  const deployResult = await Effect.runPromise(
    ContractExecutable.make(compiledContract)
      .initialize(initialPrivateState, ...constructorArgs)
      .pipe(
        Effect.provide(
          ZKFileConfiguration.layer(CompiledContract.getCompiledAssetsPath(compiledContract)),
        ),
        Effect.provide(NodeContext.layer),
        Effect.provide(keysLayer),
      ),
  );

  const fullState = ledger.ContractState.deserialize(deployResult.public.contractState.serialize());

  // Rebuild a base state carrying the same primary data and maintenance authority, but only the
  // BASE operations. Every other circuit's verifier key travels out for the caller to
  // maintenance-add, which is what keeps the deploy tx under the block limit.
  const keep = new Set(baseCircuitIds);
  const base = new ledger.ContractState();
  base.data = fullState.data;
  base.maintenanceAuthority = fullState.maintenanceAuthority;
  const deferred: DeferredCircuit[] = [];
  const kept = new Set<string>();
  for (const id of fullState.operations()) {
    const op = fullState.operation(id);
    if (!op) continue;
    const name = operationIdToString(id);
    if (keep.has(name)) {
      base.setOperation(id, op);
      kept.add(name);
    } else {
      deferred.push({ circuitId: name, verifierKey: op.verifierKey });
    }
  }
  // A baseCircuitIds entry that matched nothing (a typo, or a renamed circuit) would
  // otherwise silently defer everything and deploy a zero-operation base.
  const unmatched = baseCircuitIds.filter((id) => !kept.has(id));
  if (unmatched.length > 0) {
    throw new Error(
      `baseCircuitIds ${unmatched.map((id) => `"${id}"`).join(", ")} match no compiled circuit. ` +
        `compiled circuits: ${[...fullState.operations()].map(operationIdToString).join(", ")}`,
    );
  }

  const deploy = new ledger.ContractDeploy(base);
  const intent = ledger.Intent.new(new Date(Date.now() + DEPLOY_TTL_MS)).addDeploy(deploy);
  const transaction = ledger.Transaction.fromPartsRandomized(
    networkId,
    undefined,
    undefined,
    intent,
  );

  return {
    contractAddress: deploy.address,
    serializedTransaction: transaction.serialize(),
    deferred,
  };
}

/**
 * Build an unproven maintenance-update transaction that inserts `verifierKey` under `circuitId`
 * on the deployed contract at `contractAddress`, signed by the `MAINTENANCE_SIGNING_KEY` authority.
 * Ledger-level operation-version `'v4'` (which accepts the v7 verifier keys the compiler emits),
 * the path proven to be accepted on-chain. Binds to the authority counter read from
 * `currentContractStateBytes`, so re-query the live state before each add.
 *
 * @param networkId - The network the transaction targets.
 * @param env - The environment carrying `MAINTENANCE_SIGNING_KEY` (the authority that signs the update).
 * @param contractAddress - The deployed contract's address (hex).
 * @param circuitId - The circuit id to install `verifierKey` under.
 * @param verifierKey - The new circuit's verifier key bytes.
 * @param currentContractStateBytes - Serialized live contract state (from queryContractState).
 * @returns The serialized unproven maintenance transaction.
 * @throws {Error} If `MAINTENANCE_SIGNING_KEY` is unset or malformed.
 */
export function buildMaintenanceInsertTransaction(
  networkId: NetworkId,
  env: Record<string, string | undefined>,
  contractAddress: string,
  circuitId: string,
  verifierKey: Uint8Array,
  currentContractStateBytes: Uint8Array,
): { serializedTransaction: Uint8Array } {
  const hex = maintenanceSigningKeyHex(env);
  if (!hex) {
    throw new Error(
      "MAINTENANCE_SIGNING_KEY must be set to sign a maintenance update for the contract's authority.",
    );
  }

  const contractState = ledger.ContractState.deserialize(currentContractStateBytes);
  const counter = contractState.maintenanceAuthority.counter;

  const versionedKey = new ledger.ContractOperationVersionedVerifierKey("v4", verifierKey);
  const insert = new ledger.VerifierKeyInsert(circuitId, versionedKey);
  let update = new ledger.MaintenanceUpdate(contractAddress, [insert], counter);
  const signingKey = ledger.signingKeyFromBip340(Uint8Array.from(Buffer.from(hex, "hex")));
  update = update.addSignature(0n, ledger.signData(signingKey, update.dataToSign));

  const intent = ledger.Intent.new(new Date(Date.now() + DEPLOY_TTL_MS)).addMaintenanceUpdate(
    update,
  );
  const transaction = ledger.Transaction.fromPartsRandomized(
    networkId,
    undefined,
    undefined,
    intent,
  );
  return { serializedTransaction: transaction.serialize() };
}

/**
 * The contract maintenance authority signing key, read from
 * `MAINTENANCE_SIGNING_KEY` (32-byte BIP-340 key as hex, `0x` optional).
 * Present makes the deployed contract's authority this key, so it can gain
 * circuits via a maintenance update later; the same secret must sign those
 * updates. Absent yields `Option.none()`, leaving the contract unmaintainable.
 *
 * @param env - The environment to read `MAINTENANCE_SIGNING_KEY` from.
 * @returns The maintenance authority key, or none when the env var is unset.
 * @throws {Error} If `MAINTENANCE_SIGNING_KEY` is set but not 32 bytes of hex.
 */
export function resolveMaintenanceSigningKey(
  env: Record<string, string | undefined>,
): Option.Option<SigningKey.SigningKey> {
  const hex = maintenanceSigningKeyHex(env);
  return hex ? Option.some(SigningKey.make(hex)) : Option.none();
}
