// The vault's deploy flow: build, balance, prove and submit the split deploy
// transaction using the wallet and node-config plumbing of
// @sig-net/midnight-contract-deploy and the split-deploy builders of
// @sig-net/midnight-examples-lib. Everything contract-specific lives HERE: the constructor args (deployerCommitment, the
// signet contract reference), the witnesses, and the private state. Requires
// `npm run compile` output (verifier keys) in the contract package's managed
// dir. The MPC response key is NOT a deploy input: it derives from the new
// contract's own address, so the deployer-gated initialise circuit pins it
// right after deploy (see {@link file://./initialise-vault.ts}).

import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { computeSha256Hex } from "@midnight-ntwrk/midnight-js/utils";
import {
  type IndexerPublicDataProvider,
  indexerPublicDataProvider,
} from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import * as ledger from "@midnightntwrk/ledger-v9";
import { contractAddressFromHex } from "@sig-net/midnight";
import {
  CounterpartyOrigin,
  ensureFeeReady,
  envOrUndefined,
  estimateUnprovenTransactionFee,
  formatDust,
  getDeployConfig,
  getFaucetUrl,
  isLocalStandaloneNetwork,
  type MidnightNodeConfig,
  type NetworkId,
  parseIdentitySecretKey,
  type RegisteredWallet,
  resolveSignetContractAddress,
  submitUnprovenTransaction,
  type TransactionIdentifier,
  WalletRegistry,
} from "@sig-net/midnight-contract-deploy";
import { createVaultPrivateState, expectedVk, pureCircuits } from "../contract/src/index.ts";
import {
  buildDeployTransactionDeferring,
  buildMaintenanceInsertTransaction,
  type DeferredCircuit,
  installedCircuitIds,
  SplitDeployAfterBaseSubmitError,
  type SplitDeployTransaction,
} from "../lib/deploy.ts";

import { VAULT_MANAGED_PATH, vaultCompiledContract } from "./vault-contract-binding.ts";

// The full 17-circuit deploy overflows a block. Even the 9 core circuits overflow it (the
// post-burn keys are large), so the base registers just ONE small circuit and every other
// circuit is added by a maintenance update right after (each a tiny, fitting tx).
const BASE_DEPLOY_CIRCUITS: readonly string[] = ["approveRouter"];

const MINUTE_MS = 60_000;
// Funding must finish within the base intent's 30-minute lifetime.
const DEPLOY_FUNDING_TIMEOUT_MS: number = 20 * MINUTE_MS;
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Read the live contract state's serialized bytes and authority counter, or undefined if the
 * contract is not yet on the indexer.
 *
 * @param pdp - The indexer public-data provider.
 * @param contractAddress - The contract address to read.
 * @returns The serialized state and its maintenance-authority counter, or undefined.
 */
async function readContractState(
  pdp: IndexerPublicDataProvider,
  contractAddress: string,
): Promise<{ serialized: Uint8Array; counter: bigint } | undefined> {
  const state = await pdp.queryContractState(contractAddress);
  if (!state) return undefined;
  const serialized = state.serialize();
  const counter = ledger.ContractState.deserialize(serialized).maintenanceAuthority.counter;
  return { serialized, counter };
}

/**
 * The circuits to install before any other deferred one. `initialise` first:
 * a run that dies after that add leaves a contract `yarn initialise:erc20-vault`
 * can already initialise while the resume installs the rest.
 */
const FIRST_DEFERRED_CIRCUITS: readonly string[] = ["initialise"];

/**
 * The order the deferred circuits are installed in: {@link FIRST_DEFERRED_CIRCUITS}
 * first, in their listed order, then the rest in the order given.
 *
 * @param deferred - The circuits held back from the base deploy, in ledger order.
 * @returns The same circuits, reordered.
 */
export function orderDeferredCircuits(deferred: readonly DeferredCircuit[]): DeferredCircuit[] {
  const first = FIRST_DEFERRED_CIRCUITS.flatMap((id) =>
    deferred.filter((circuit) => circuit.circuitId === id),
  );
  return [
    ...first,
    ...deferred.filter((circuit) => !FIRST_DEFERRED_CIRCUITS.includes(circuit.circuitId)),
  ];
}

/**
 * Install the circuits deferred from the base deploy via one maintenance update each, in
 * {@link orderDeferredCircuits} order, waiting for the authority counter to advance between them
 * so every update binds to the current counter. Each update waits for the deployer's running
 * facade to catch up (fresh fee coins) and to hold that update's estimated fee, and is
 * signed by the `MAINTENANCE_SIGNING_KEY` authority sealed at deploy time.
 *
 * @param nodeConfig - The Midnight stack config (node/indexer endpoints + network id).
 * @param env - The environment carrying the `MAINTENANCE_SIGNING_KEY` that signs each update.
 * @param deployer - The deployer's started wallet (pays the update fees).
 * @param networkId - The network the updates target.
 * @param contractAddress - The deployed base contract's address.
 * @param deferred - The circuits to add.
 * @throws {WalletUnfundedError} If the deployer wallet holds neither NIGHT nor DUST before an add.
 * @throws {Error} If the base deploy never indexes, an update's fee does not generate in
 *   spendable DUST after registering the wallet's NIGHT, or an add's counter never advances.
 */
async function addDeferredCircuits(
  nodeConfig: MidnightNodeConfig,
  env: Record<string, string | undefined>,
  deployer: RegisteredWallet,
  networkId: NetworkId,
  contractAddress: string,
  deferred: readonly DeferredCircuit[],
): Promise<void> {
  if (deferred.length === 0) return;
  const pdp = indexerPublicDataProvider({
    queryURL: nodeConfig.indexerUrl,
    subscriptionURL: nodeConfig.indexerWsUrl,
  });
  try {
    await addDeferredCircuitsThrough(pdp, env, deployer, networkId, contractAddress, deferred);
  } finally {
    // The provider holds a WebSocket that would otherwise keep the entrypoint alive.
    await pdp.dispose();
  }
}

// The body of {@link addDeferredCircuits}, against a provider the caller disposes.
async function addDeferredCircuitsThrough(
  pdp: IndexerPublicDataProvider,
  env: Record<string, string | undefined>,
  deployer: RegisteredWallet,
  networkId: NetworkId,
  contractAddress: string,
  deferred: readonly DeferredCircuit[],
): Promise<void> {
  // Wait for the base deploy to be indexed before the first maintenance query.
  const indexDeadline = Date.now() + 5 * MINUTE_MS;
  while (!(await readContractState(pdp, contractAddress))) {
    if (Date.now() > indexDeadline) {
      throw new Error(`base deploy ${contractAddress} was not indexed within 5 minutes`);
    }
    await sleep(3000);
  }

  const ordered = orderDeferredCircuits(deferred);
  for (const { circuitId, verifierKey } of ordered) {
    const current = await readContractState(pdp, contractAddress);
    if (!current) throw new Error(`contract state for ${contractAddress} vanished mid-deploy`);
    console.log(`[${circuitId}] maintenance-add at counter ${current.counter.toString()}`);

    const { serializedTransaction } = buildMaintenanceInsertTransaction(
      networkId,
      env,
      contractAddress,
      circuitId,
      verifierKey,
      current.serialized,
    );
    const fee = await estimateUnprovenTransactionFee(deployer.facade, serializedTransaction);
    console.log(`[${circuitId}] estimated fee: ${formatDust(fee)} DUST`);
    const state = await deployer.facade.waitForSyncedState();
    await ensureFeeReady(
      deployer.facade,
      deployer.keys,
      state,
      networkId,
      getFaucetUrl(env, networkId),
      fee,
      DEPLOY_FUNDING_TIMEOUT_MS,
    );
    const txId = await submitUnprovenTransaction(
      deployer.facade,
      deployer.keys,
      serializedTransaction,
    );
    const target = current.counter + 1n;
    console.log(`[${circuitId}] maintenance tx ${txId}, waiting for counter ${target.toString()}`);

    const deadline = Date.now() + 5 * MINUTE_MS;
    for (;;) {
      await sleep(5000);
      const now = await readContractState(pdp, contractAddress);
      if (now && now.counter >= target) {
        console.log(`[${circuitId}] confirmed at counter ${now.counter.toString()}`);
        break;
      }
      if (Date.now() > deadline) {
        throw new Error(`[${circuitId}] timed out waiting for counter ${target.toString()}`);
      }
    }
  }
}

/**
 * Resolve the environment the deploy signs its maintenance updates with. The split deploy adds the
 * deferred circuits via maintenance updates, so the contract needs a maintenance authority: on a
 * deployed network `MAINTENANCE_SIGNING_KEY` is REQUIRED, since it is the only way to add or
 * replace a circuit afterwards and an ephemeral one would leave the contract unmaintainable
 * forever. The local standalone chain is throwaway, so an ephemeral key is generated into a COPY
 * of `env` (never `process.env`, and never the caller's map) and printed: the deploy and its adds
 * all run inside this one call, and the printed value is what a {@link resumeVaultDeploy} after a
 * failed add exports, since the adds must be signed by the authority the base deploy sealed.
 *
 * @param env - The caller's environment.
 * @param networkId - The network the deploy targets.
 * @returns `env` itself, or a copy carrying a generated ephemeral key.
 * @throws {Error} If a deployed network has no `MAINTENANCE_SIGNING_KEY`.
 */
function resolveMaintenanceEnv(
  env: Record<string, string | undefined>,
  networkId: NetworkId,
): Record<string, string | undefined> {
  if (envOrUndefined(env, "MAINTENANCE_SIGNING_KEY")) return env;
  if (!isLocalStandaloneNetwork(networkId)) {
    throw new Error(
      `MAINTENANCE_SIGNING_KEY is required on "${networkId}". The split deploy installs most ` +
        "circuits via maintenance updates, and the key signing them becomes the contract's sealed " +
        "maintenance authority, the only way to add or replace a circuit later. Set it to 32 " +
        "bytes of hex (0x optional) and KEEP it.",
    );
  }
  const maintenanceSigningKey = randomBytes(32).toString("hex");
  console.log(
    `generated an ephemeral MAINTENANCE_SIGNING_KEY for the local split deploy: ${maintenanceSigningKey}`,
  );
  console.log(
    "  (export it as MAINTENANCE_SIGNING_KEY to `yarn resume-deploy:erc20-vault` if a maintenance add fails)",
  );
  return { ...env, MAINTENANCE_SIGNING_KEY: maintenanceSigningKey };
}

/**
 * Price the base deployment and every deferred verifier-key insertion individually.
 * Balancing inputs and later price changes can increase the submitted fees.
 *
 * @param deployment - The base transaction and deferred verifier keys.
 * @param networkId - The deployment network.
 * @param env - The maintenance signing key for the deferred insertions.
 * @param estimateFee - Price one serialized unproven transaction in SPECKs.
 * @returns The combined estimated fee in SPECKs.
 * @throws {Error} If the base transaction contains no deployment or an estimate fails.
 */
export async function estimateVaultDeploymentFee(
  deployment: SplitDeployTransaction,
  networkId: NetworkId,
  env: Record<string, string | undefined>,
  estimateFee: (transaction: Uint8Array) => Promise<bigint>,
): Promise<bigint> {
  const transaction: ledger.UnprovenTransaction = ledger.Transaction.deserialize(
    "signature",
    "pre-proof",
    "pre-binding",
    deployment.serializedTransaction,
  );
  const base = [...(transaction.intents?.values() ?? [])]
    .flatMap((intent) => intent.actions)
    .find((action): action is ledger.ContractDeploy => action instanceof ledger.ContractDeploy);
  if (!base) throw new Error("fee estimation requires a base contract deployment");
  const state: ledger.ContractState = base.initialState;
  let total: bigint = await estimateFee(deployment.serializedTransaction);
  for (const { circuitId, verifierKey } of orderDeferredCircuits(deployment.deferred)) {
    const { serializedTransaction } = buildMaintenanceInsertTransaction(
      networkId,
      env,
      deployment.contractAddress,
      circuitId,
      verifierKey,
      state.serialize(),
    );
    total += await estimateFee(serializedTransaction);
    const authority: ledger.ContractMaintenanceAuthority = state.maintenanceAuthority;
    state.maintenanceAuthority = new ledger.ContractMaintenanceAuthority(
      authority.committee,
      authority.threshold,
      authority.counter + 1n,
    );
  }
  return total;
}

/** The outcome of a successful vault deployment. */
export interface VaultDeployment {
  /** Address of the deployed vault contract on Midnight. */
  readonly contractAddress: string;
  /** Identifier of the submitted base deploy transaction. */
  readonly txId: TransactionIdentifier;
}

/**
 * Deploy the vault contract: read config from `env`, derive the deployer
 * identity, build/prove the base deploy transaction, submit it through a synced
 * wallet, then install every deferred circuit by a maintenance update. Progress
 * is logged to the console.
 *
 * The deployer identity comes from `VAULT_DEPLOYER_SECRET_KEY` (falling back
 * to the `DEPLOYER_SEED` bytes): its commitment is sealed into the contract
 * as `deployer`, and the same secret must later answer the `callerSecretKey`
 * witness to pass `initialise`'s gate. That gate is what protects the
 * post-deploy configuration (vault EVM address, chain, MPC response key)
 * from front-running (see {@link file://./initialise-vault.ts}).
 *
 * @param env - Environment providing `DEPLOYER_SEED`, `VAULT_DEPLOYER_SECRET_KEY`,
 *   `MAINTENANCE_SIGNING_KEY` and the deploy SDK's Midnight node configuration, plus
 *   `MIDNIGHT_SIGNET_CONTRACT_ADDRESS` where the SDK publishes no signet singleton
 *   for the network (see `resolveSignetContractAddress`). Defaults to `process.env`.
 * @param wallets - A registry to take the deployer wallet from, when the caller keeps wallets
 *   open across steps (the e2e setup pipeline). Without one, a private registry is opened for
 *   this deploy and closed after it.
 * @param onBaseDeploySubmitted - Called with the contract address once the base deploy
 *   transaction is submitted and before the first maintenance add: from here the contract is
 *   live and a rerun would deploy a second one, so a caller that persists the address for
 *   {@link resumeVaultDeploy} does it here.
 * @returns The deployed contract address and base deploy transaction id.
 * @throws {WalletUnfundedError} If the deployer wallet holds neither NIGHT nor
 *   DUST: the error carries the wallet's NIGHT receive address to fund.
 * @throws {Error} If no signet singleton resolves (see `resolveSignetContractAddress`),
 *   `MAINTENANCE_SIGNING_KEY` is missing on a deployed network, the fee of the base deploy
 *   plus one add per deferred circuit does not generate in spendable DUST after registering
 *   the wallet's NIGHT, or the base deploy submission fails.
 * @throws {SplitDeployAfterBaseSubmitError} If installing the deferred
 *   circuits fails after the base deploy was submitted: a rerun would deploy
 *   a second contract, so callers must not retry on it.
 */
export async function deployVault(
  env: Record<string, string | undefined> = process.env,
  wallets?: WalletRegistry,
  onBaseDeploySubmitted?: (contractAddress: string) => void,
): Promise<VaultDeployment> {
  const deployConfig = getDeployConfig(env);
  const { networkId } = deployConfig.midnightNodeConfig;
  const deployEnv = resolveMaintenanceEnv(env, networkId);
  const registry = wallets ?? new WalletRegistry(deployConfig.midnightNodeConfig);
  try {
    const secretKey = parseIdentitySecretKey(
      "VAULT_DEPLOYER_SECRET_KEY",
      env,
      deployConfig.deployerSeed,
    );
    const deployerCommitment = pureCircuits.userCommitment(secretKey);

    // The signet contract the vault cross-contract-calls to register signature
    // request notifications, sealed into the vault as the SignetSigner
    // reference: the singleton the SDK publishes for a deployed network, or the
    // one MIDNIGHT_SIGNET_CONTRACT_ADDRESS names.
    const signet = resolveSignetContractAddress(env);
    console.log(
      `signet singleton ${signet.value} ` +
        (signet.origin === CounterpartyOrigin.Published
          ? `(published by the SDK for ${networkId})`
          : "(MIDNIGHT_SIGNET_CONTRACT_ADDRESS)"),
    );
    const signetSigner = contractAddressFromHex(signet.value);

    console.log(
      `deploying erc20-vault to ${networkId} (${deployConfig.midnightNodeConfig.nodeUrl})`,
    );
    const deployer = await registry.wallet(deployConfig.deployerSeed, "deployer");

    const deployTransaction = await buildDeployTransactionDeferring(
      vaultCompiledContract,
      networkId,
      deployer.keys.shieldedSecretKeys.coinPublicKey,
      deployEnv,
      createVaultPrivateState(secretKey),
      BASE_DEPLOY_CIRCUITS,
      deployerCommitment,
      signetSigner,
    );
    const { contractAddress, deferred } = deployTransaction;
    console.log(`contract address (pre-submit): ${contractAddress}`);
    console.log(
      `base deploy registers ${String(BASE_DEPLOY_CIRCUITS.length)} circuit(s); ` +
        `deferring ${String(deferred.length)} for maintenance adds`,
    );

    const transactionCount: number = 1 + deferred.length;
    const feeBudget: bigint = await estimateVaultDeploymentFee(
      deployTransaction,
      networkId,
      deployEnv,
      (transaction: Uint8Array): Promise<bigint> =>
        estimateUnprovenTransactionFee(deployer.facade, transaction),
    );
    console.log(
      `estimated fee budget: ${formatDust(feeBudget)} DUST for ${String(transactionCount)} individually priced transactions (balancing fees additional)`,
    );
    const state = await deployer.facade.waitForSyncedState();
    await ensureFeeReady(
      deployer.facade,
      deployer.keys,
      state,
      networkId,
      getFaucetUrl(env, networkId),
      feeBudget,
      DEPLOY_FUNDING_TIMEOUT_MS,
    );
    const txId = await submitUnprovenTransaction(
      deployer.facade,
      deployer.keys,
      deployTransaction.serializedTransaction,
    );
    // From here the contract is live: a failure below is reported as
    // SplitDeployAfterBaseSubmitError, and the address line is what a resume
    // takes.
    console.log(`submitted base deploy tx ${txId}`);
    console.log(`deployed erc20-vault base at ${contractAddress}`);
    onBaseDeploySubmitted?.(contractAddress);

    try {
      await addDeferredCircuits(
        deployConfig.midnightNodeConfig,
        deployEnv,
        deployer,
        networkId,
        contractAddress,
        deferred,
      );
    } catch (error) {
      throw new SplitDeployAfterBaseSubmitError(
        `installing the deferred circuits on ${contractAddress} failed after its base deploy ` +
          "was submitted",
        { cause: error },
      );
    }
    console.log(
      `deployed erc20-vault at ${contractAddress} ` +
        `(all ${String(deferred.length + BASE_DEPLOY_CIRCUITS.length)} circuits installed)`,
    );

    return { contractAddress, txId };
  } finally {
    if (wallets === undefined) await registry.close();
  }
}

/** The outcome of {@link resumeVaultDeploy}. */
export interface ResumedVaultDeploy {
  /** Address of the vault the resume ran against. */
  readonly contractAddress: string;
  /** The circuit ids this call installed, in the order they were added. */
  readonly installed: readonly string[];
}

/**
 * The deferred-circuit records for `circuitIds`, read from the contract package's compiled
 * verifier keys, each checked against the generated module's `expectedVk` digest so a checkout
 * whose keys differ from its module cannot install a key the module's proofs will not verify
 * against.
 *
 * @param circuitIds - The circuits to read keys for.
 * @returns One record per circuit, in the given order.
 * @throws {Error} If a key file is missing (run `yarn compile:erc20-vault:zk`) or its digest is not
 *   the module's expected one.
 */
export function readDeferredCircuits(circuitIds: readonly string[]): DeferredCircuit[] {
  return circuitIds.map((circuitId) => {
    const path = join(VAULT_MANAGED_PATH, "keys", `${circuitId}.verifier`);
    let verifierKey: Uint8Array;
    try {
      verifierKey = new Uint8Array(readFileSync(path));
    } catch (error) {
      throw new Error(
        `no verifier key for ${circuitId} at ${path}: run \`yarn compile:erc20-vault:zk\``,
        {
          cause: error,
        },
      );
    }
    const digest = computeSha256Hex(verifierKey);
    const expected = expectedVk[circuitId];
    if (digest !== expected) {
      throw new Error(
        `verifier key ${path} has digest ${digest}, but the generated module expects ${String(expected)}: ` +
          "the keys and the module come from different compiles",
      );
    }
    return { circuitId, verifierKey };
  });
}

/**
 * Finish a split deploy that died after its base deploy landed: read the live contract, install
 * every provable circuit it lacks by a maintenance update each (same order, same authority and
 * same fee wallet as {@link deployVault}), and leave the contract ready for
 * `yarn initialise:erc20-vault`. Idempotent: a contract with every circuit installed is a no-op.
 * The verifier keys come from the checkout's compiled output, checked against the generated
 * module, so the checkout must be the one the contract was deployed from (same tag, `compile:zk`
 * run).
 *
 * @param env - Environment providing `DEPLOYER_SEED`, `MAINTENANCE_SIGNING_KEY` (the authority
 *   sealed at deploy, without which no circuit can be installed: a vault with every circuit
 *   already installed needs neither) and the deploy SDK's Midnight node configuration.
 *   Defaults to `process.env`.
 * @param contractAddress - The vault to resume. Defaults to `MIDNIGHT_VAULT_CONTRACT_ADDRESS`.
 * @param wallets - A registry to take the deployer wallet from. Without one a private registry
 *   is opened for this resume and closed after it.
 * @returns The address and the circuits this call installed.
 * @throws {WalletUnfundedError} If the deployer wallet holds neither NIGHT nor DUST before an add.
 * @throws {Error} If no address is available, no contract answers at the address, or circuits
 *   are missing and `MAINTENANCE_SIGNING_KEY` is unset, a verifier key is missing or
 *   mismatched, or an add fails.
 */
export async function resumeVaultDeploy(
  env: Record<string, string | undefined> = process.env,
  contractAddress?: string,
  wallets?: WalletRegistry,
): Promise<ResumedVaultDeploy> {
  const explicitAddress = contractAddress?.trim();
  const vaultContractAddress =
    explicitAddress === undefined || explicitAddress === ""
      ? envOrUndefined(env, "MIDNIGHT_VAULT_CONTRACT_ADDRESS")
      : explicitAddress;
  if (!vaultContractAddress) {
    throw new Error(
      "MIDNIGHT_VAULT_CONTRACT_ADDRESS is required to resume a deploy: the interrupted run printed " +
        'it as "deployed erc20-vault base at <address>"',
    );
  }
  const deployConfig = getDeployConfig(env);
  const nodeConfig = deployConfig.midnightNodeConfig;
  const { networkId } = nodeConfig;

  const pdp = indexerPublicDataProvider({
    queryURL: nodeConfig.indexerUrl,
    subscriptionURL: nodeConfig.indexerWsUrl,
  });
  let installed: string[];
  try {
    const live = await readContractState(pdp, vaultContractAddress);
    if (!live) {
      throw new Error(
        `no contract at ${vaultContractAddress} on ${networkId} (${nodeConfig.indexerUrl})`,
      );
    }
    installed = installedCircuitIds(live.serialized);
  } finally {
    await pdp.dispose();
  }

  const missing = Object.keys(expectedVk).filter((circuitId) => !installed.includes(circuitId));
  console.log(
    `resuming erc20-vault ${vaultContractAddress} on ${networkId}: ` +
      `${String(installed.length)} circuit(s) installed, ${String(missing.length)} missing` +
      (missing.length > 0 ? ` (${missing.join(", ")})` : ""),
  );
  if (missing.length === 0) {
    return { contractAddress: vaultContractAddress, installed: [] };
  }
  if (!envOrUndefined(env, "MAINTENANCE_SIGNING_KEY")) {
    throw new Error(
      "MAINTENANCE_SIGNING_KEY is required to resume a deploy: the maintenance adds must be signed " +
        "by the authority sealed at the base deploy. A local run printed the ephemeral key it " +
        "generated just before the base deploy.",
    );
  }

  const deferred = orderDeferredCircuits(readDeferredCircuits(missing));
  const registry = wallets ?? new WalletRegistry(nodeConfig);
  try {
    const deployer = await registry.wallet(deployConfig.deployerSeed, "deployer");
    await addDeferredCircuits(nodeConfig, env, deployer, networkId, vaultContractAddress, deferred);
  } finally {
    if (wallets === undefined) await registry.close();
  }
  console.log(
    `resumed erc20-vault at ${vaultContractAddress} ` +
      `(all ${String(Object.keys(expectedVk).length)} circuits installed)`,
  );
  return { contractAddress: vaultContractAddress, installed: deferred.map((c) => c.circuitId) };
}
