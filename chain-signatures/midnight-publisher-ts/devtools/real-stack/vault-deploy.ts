import { randomBytes } from "node:crypto";
import { NodeContext } from "@effect/platform-node";
import { ContractExecutable } from "@midnight-ntwrk/compact-js/effect";
import { ZKFileConfiguration } from "@midnight-ntwrk/compact-js-node/effect";
import type { PublicDataProvider } from "@midnight-ntwrk/midnight-js/types";
import * as CoinPublicKey from "@midnight-ntwrk/platform-js/effect/CoinPublicKey";
import * as Configuration from "@midnight-ntwrk/platform-js/effect/Configuration";
import * as SigningKey from "@midnight-ntwrk/platform-js/effect/SigningKey";
import * as ledger from "@midnightntwrk/ledger-v9";
import type { WalletFacade } from "@midnightntwrk/wallet-sdk-facade";
import { contractAddressFromHex } from "@sig-net/midnight";
import { submitUnprovenTransaction, type AccountKeys } from "@sig-net/midnight-contract-deploy";
import { Effect, Layer, Option } from "effect";
import { pureCircuits } from "./managed/erc20-vault/contract/index.js";
import { vaultCompiledContract, vaultManagedPath } from "./vault-contract.js";

// Every verifier key in one deploy overflows a block, so the base deploy registers one
// small circuit and maintenance updates install the rest, a few kilobytes of keys each.
const BASE_CIRCUIT = "approveRouter";
const MAINTENANCE_BATCH_BYTES = 12_000;
const TTL_MS = 30 * 60_000;

const circuitName = (id: string | Uint8Array) =>
  typeof id === "string" ? id : new TextDecoder().decode(id);

function batches(state: ledger.ContractState): ledger.VerifierKeyInsert[][] {
  const result: ledger.VerifierKeyInsert[][] = [];
  let batch: ledger.VerifierKeyInsert[] = [];
  let bytes = 0;
  for (const id of state.operations()) {
    const name = circuitName(id);
    const operation = state.operation(id);
    if (name === BASE_CIRCUIT || operation === undefined) continue;
    if (batch.length > 0 && bytes + operation.verifierKey.length > MAINTENANCE_BATCH_BYTES) {
      result.push(batch);
      batch = [];
      bytes = 0;
    }
    batch.push(
      new ledger.VerifierKeyInsert(
        name,
        new ledger.ContractOperationVersionedVerifierKey("v4", operation.verifierKey),
      ),
    );
    bytes += operation.verifierKey.length;
  }
  if (batch.length > 0) result.push(batch);
  return result;
}

async function waitForCounter(
  publicDataProvider: PublicDataProvider,
  address: string,
  counter: bigint,
): Promise<ledger.ContractState> {
  const deadline = Date.now() + 300_000;
  while (Date.now() < deadline) {
    const state = await publicDataProvider.queryContractState(address);
    if (state) {
      const current = ledger.ContractState.deserialize(state.serialize());
      if (current.maintenanceAuthority.counter >= counter) return current;
    }
    await new Promise((resolve) => setTimeout(resolve, 2_000));
  }
  throw new Error(`vault ${address} did not reach maintenance counter ${counter}`);
}

/**
 * Deploys the vault with the deployer's identity commitment, then installs its remaining
 * verifier keys under a throwaway maintenance authority.
 */
export async function deployVault(
  facade: WalletFacade,
  keys: AccountKeys,
  publicDataProvider: PublicDataProvider,
  networkId: string,
  centralAddress: string,
  deployerSecret: Uint8Array,
): Promise<string> {
  const maintenanceKey = randomBytes(32);
  const initialized = await Effect.runPromise(
    ContractExecutable.make(vaultCompiledContract)
      .initialize(
        { secretKey: deployerSecret },
        pureCircuits.userCommitment(deployerSecret),
        contractAddressFromHex(centralAddress),
      )
      .pipe(
        Effect.provide(ZKFileConfiguration.layer(vaultManagedPath)),
        Effect.provide(NodeContext.layer),
        Effect.provide(
          Layer.succeed(Configuration.Keys, {
            coinPublicKey: CoinPublicKey.Hex(keys.shieldedSecretKeys.coinPublicKey),
            getSigningKey: () => Option.some(SigningKey.make(maintenanceKey.toString("hex"))),
          }),
        ),
      ),
  );
  const full = ledger.ContractState.deserialize(initialized.public.contractState.serialize());
  const base = new ledger.ContractState();
  base.data = full.data;
  base.maintenanceAuthority = full.maintenanceAuthority;
  const baseOperation = full.operation(BASE_CIRCUIT);
  if (!baseOperation) throw new Error(`the vault has no ${BASE_CIRCUIT} circuit`);
  base.setOperation(BASE_CIRCUIT, baseOperation);
  const deployment = new ledger.ContractDeploy(base);
  const address = deployment.address;
  await submitUnprovenTransaction(
    facade,
    keys,
    ledger.Transaction.fromPartsRandomized(
      networkId,
      undefined,
      undefined,
      ledger.Intent.new(new Date(Date.now() + TTL_MS)).addDeploy(deployment),
    ).serialize(),
  );
  let current = await waitForCounter(
    publicDataProvider,
    address,
    base.maintenanceAuthority.counter,
  );
  const signingKey = ledger.signingKeyFromBip340(maintenanceKey);
  for (const inserts of batches(full)) {
    let update = new ledger.MaintenanceUpdate(
      address,
      inserts,
      current.maintenanceAuthority.counter,
    );
    update = update.addSignature(0n, ledger.signData(signingKey, update.dataToSign));
    await facade.waitForSyncedState();
    await submitUnprovenTransaction(
      facade,
      keys,
      ledger.Transaction.fromPartsRandomized(
        networkId,
        undefined,
        undefined,
        ledger.Intent.new(new Date(Date.now() + TTL_MS)).addMaintenanceUpdate(update),
      ).serialize(),
    );
    current = await waitForCounter(
      publicDataProvider,
      address,
      current.maintenanceAuthority.counter + 1n,
    );
  }
  const missing = [...full.operations()]
    .map(circuitName)
    .filter((name) => current.operation(name) === undefined);
  if (missing.length > 0) throw new Error(`vault circuits not installed: ${missing.join(", ")}`);
  return address;
}
