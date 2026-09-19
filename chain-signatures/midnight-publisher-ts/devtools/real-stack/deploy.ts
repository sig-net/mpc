import { randomBytes } from "node:crypto";
import { NodeContext } from "@effect/platform-node";
import { ContractExecutable } from "@midnight-ntwrk/compact-js/effect";
import { ZKFileConfiguration } from "@midnight-ntwrk/compact-js-node/effect";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import * as CoinPublicKey from "@midnight-ntwrk/platform-js/effect/CoinPublicKey";
import * as Configuration from "@midnight-ntwrk/platform-js/effect/Configuration";
import * as SigningKey from "@midnight-ntwrk/platform-js/effect/SigningKey";
import * as ledger from "@midnightntwrk/ledger-v9";
import { contractAddressFromHex } from "@sig-net/midnight";
import {
  deriveAccountKeys,
  submitUnprovenTransaction,
  withSyncedWalletFacade,
  type MidnightNodeConfig,
} from "@sig-net/midnight-contract-deploy";
import { Effect, Layer, Option } from "effect";
import { DEPLOYER_SEED } from "./funding.js";
import { pureCircuits } from "./managed/erc20-vault/contract/index.js";
import { vaultCompiledContract, vaultManagedPath } from "./providers.js";
import { createPrivateState } from "./witnesses.js";

// Keep the vault deployment small by installing verifier keys in separate
// maintenance updates; the SDK submits each transaction.
export async function deployVault(
  config: MidnightNodeConfig,
  centralAddress: string,
): Promise<string> {
  const keys = deriveAccountKeys(DEPLOYER_SEED, config.networkId);
  const secretKey = Uint8Array.from(Buffer.from(DEPLOYER_SEED, "hex"));
  const maintenanceKey = randomBytes(32);
  const initialized = await Effect.runPromise(
    ContractExecutable.make(vaultCompiledContract)
      .initialize(
        createPrivateState(secretKey),
        pureCircuits.userCommitment(secretKey),
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
  const fullState = ledger.ContractState.deserialize(initialized.public.contractState.serialize());
  const baseState = new ledger.ContractState();
  baseState.data = fullState.data;
  baseState.maintenanceAuthority = fullState.maintenanceAuthority;
  const baseOperation = fullState.operation("approveRouter");
  if (!baseOperation) throw new Error("vault has no approveRouter circuit");
  baseState.setOperation("approveRouter", baseOperation);
  const deployment = new ledger.ContractDeploy(baseState);
  const contractAddress = deployment.address;
  const deferred = [...fullState.operations()]
    .map((id) => (typeof id === "string" ? id : new TextDecoder().decode(id)))
    .filter((id) => id !== "approveRouter");
  const publicDataProvider = indexerPublicDataProvider({
    queryURL: config.indexerUrl,
    subscriptionURL: config.indexerWsUrl,
  });

  async function waitForState(counter: bigint): Promise<ledger.ContractState> {
    const deadline = Date.now() + 300_000;
    while (Date.now() < deadline) {
      const state = await publicDataProvider.queryContractState(contractAddress);
      if (state) {
        const current = ledger.ContractState.deserialize(state.serialize());
        if (current.maintenanceAuthority.counter >= counter) return current;
      }
      await new Promise((resolve) => setTimeout(resolve, 3_000));
    }
    throw new Error(`vault ${contractAddress} did not reach maintenance counter ${counter}`);
  }

  try {
    return await withSyncedWalletFacade(keys, config, async (facade) => {
      const deployIntent = ledger.Intent.new(new Date(Date.now() + 30 * 60_000)).addDeploy(
        deployment,
      );
      await submitUnprovenTransaction(
        facade,
        keys,
        ledger.Transaction.fromPartsRandomized(
          config.networkId,
          undefined,
          undefined,
          deployIntent,
        ).serialize(),
      );
      let current = await waitForState(baseState.maintenanceAuthority.counter);
      for (const circuitId of deferred) {
        const operation = fullState.operation(circuitId);
        if (!operation) throw new Error(`vault has no ${circuitId} circuit`);
        const insert = new ledger.VerifierKeyInsert(
          circuitId,
          new ledger.ContractOperationVersionedVerifierKey("v4", operation.verifierKey),
        );
        let update = new ledger.MaintenanceUpdate(
          contractAddress,
          [insert],
          current.maintenanceAuthority.counter,
        );
        update = update.addSignature(
          0n,
          ledger.signData(ledger.signingKeyFromBip340(maintenanceKey), update.dataToSign),
        );
        const intent = ledger.Intent.new(new Date(Date.now() + 30 * 60_000)).addMaintenanceUpdate(
          update,
        );
        await facade.waitForSyncedState();
        await submitUnprovenTransaction(
          facade,
          keys,
          ledger.Transaction.fromPartsRandomized(
            config.networkId,
            undefined,
            undefined,
            intent,
          ).serialize(),
        );
        current = await waitForState(current.maintenanceAuthority.counter + 1n);
        if (!current.operation(circuitId)) throw new Error(`vault did not install ${circuitId}`);
        console.error(`installed vault circuit ${circuitId}`);
      }
      return contractAddress;
    });
  } finally {
    await publicDataProvider.dispose();
  }
}
