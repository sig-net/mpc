// Deploy path, never shipped: `src/` must not import it, and a test asserts that. Makes
// the deployer wallet fee-ready and deploys a fresh signet singleton; the LAST line
// printed is the contract address.

import {
  deploySignetContract,
  deriveAccountKeys,
  GENESIS_MINT_WALLET_SEED,
  getMidnightNodeConfig,
  registerNightForDustGeneration,
  waitForSpendableDust,
  withSyncedWalletFacade,
} from "@sig-net/midnight-contract-deploy";

const env = process.env;
const seed = env["DEPLOYER_SEED"] ?? GENESIS_MINT_WALLET_SEED;
const config = getMidnightNodeConfig(env);
const keys = deriveAccountKeys(seed, config.networkId);

await withSyncedWalletFacade(keys, config, async (facade, state) => {
  const registered = await registerNightForDustGeneration(facade, keys, state);
  console.log(`dust: ${registered} NIGHT utxo(s) newly registered`);
  const dust = await waitForSpendableDust(facade, 180_000);
  console.log(`dust: ${dust} spendable`);
});

const { contractAddress, txId } = await deploySignetContract({ ...env, DEPLOYER_SEED: seed });
console.log(`deployed singleton in tx ${txId}`);
console.log(contractAddress);
