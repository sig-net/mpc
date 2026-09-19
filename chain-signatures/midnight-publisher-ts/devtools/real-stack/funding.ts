import {
  deriveAccountKeys,
  deriveWalletAddresses,
  GENESIS_MINT_WALLET_SEED,
  isLocalStandaloneNetwork,
  registerNightForDustGeneration,
  transferNight,
  waitForSpendableDust,
  withSyncedWalletFacade,
  type FacadeState,
  type MidnightNodeConfig,
} from "@sig-net/midnight-contract-deploy";

export const DEPLOYER_SEED = "02".repeat(32);
export const USER_SEED = "03".repeat(32);
export const PUBLISHER_SEED = "04".repeat(32);

// `assertRootFunded` returns as soon as root's spendable DUST is positive, but a
// transfer's fee may exceed that first sliver until a few more blocks of DUST
// generate. A transfer built too early fails to balance ("could not balance
// dust"); the same transfer a few blocks later succeeds. Retry only that error,
// so root's DUST can catch up without masking a genuine funding failure.
function isDustBalancingShortfall(error: unknown): boolean {
  const text = error instanceof Error ? `${error.message}\n${error.stack ?? ""}` : String(error);
  return /Wallet\.InsufficientFunds|Insufficient Funds|could not balance dust/i.test(text);
}

function totalNight(state: FacadeState): bigint {
  return Object.values(state.unshielded.balances).reduce((sum, value) => sum + value, 0n);
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

// Mirrors the package's per-child flow but amortizes the expensive part: a
// root facade re-syncs from genesis once (that re-sync dominates wall time),
// funds every role wallet sequentially from that live facade, and the
// independent child verifications run concurrently afterwards.
export async function fundRoles(config: MidnightNodeConfig): Promise<void> {
  const networkId = config.networkId;
  const rootKeys = deriveAccountKeys(GENESIS_MINT_WALLET_SEED, networkId);
  const roles = [
    ["deployer", DEPLOYER_SEED],
    ["user", USER_SEED],
    ["publisher", PUBLISHER_SEED],
  ] as const;

  await withSyncedWalletFacade(rootKeys, config, async (rootFacade, initialState) => {
    // Local standalone genesis funds root by construction, but the indexer can
    // lag before the UTXO is visible; poll like assertRootFunded does.
    let state = initialState;
    if (isLocalStandaloneNetwork(networkId)) {
      const deadline = Date.now() + 120_000;
      while (totalNight(state) === 0n && Date.now() < deadline) {
        await sleep(3_000);
        state = await rootFacade.waitForSyncedState();
      }
    }
    const amount = totalNight(state) / 5n;
    if (amount === 0n) throw new Error("local genesis wallet cannot fund role wallets");
    await registerNightForDustGeneration(rootFacade, rootKeys, state);
    if (state.dust.balance(new Date()) === 0n) await waitForSpendableDust(rootFacade);

    // Sequential: every transfer spends root UTXOs selected from `state`.
    for (const [name, seed] of roles) {
      const startedAt = Date.now();
      const unshielded = deriveWalletAddresses(seed, config).unshielded;
      for (let attempt = 0; ; attempt += 1) {
        try {
          await transferNight(rootFacade, rootKeys, state, unshielded, networkId, amount);
          break;
        } catch (error) {
          if (attempt >= 11 || !isDustBalancingShortfall(error)) throw error;
          console.error(
            `root DUST is not yet enough to cover the ${name} transfer; retrying (attempt ${attempt + 1})`,
          );
          await sleep(5_000);
          state = await rootFacade.waitForSyncedState();
        }
      }
      // Let the transfer block land before selecting UTXOs for the next one.
      await sleep(3_000);
      state = await rootFacade.waitForSyncedState();
      console.error(`funded ${name} wallet in ${Date.now() - startedAt}ms`);
    }
  });

  await Promise.all(
    roles.map(async ([name, seed]) => {
      const startedAt = Date.now();
      const keys = deriveAccountKeys(seed, networkId);
      await withSyncedWalletFacade(keys, config, async (facade, initialState) => {
        let state = initialState;
        const deadline = Date.now() + 120_000;
        while (totalNight(state) === 0n && Date.now() < deadline) {
          await sleep(3_000);
          state = await facade.waitForSyncedState();
        }
        if (totalNight(state) === 0n) {
          throw new Error(`${name} wallet shows no NIGHT after funding from root`);
        }
        await registerNightForDustGeneration(facade, keys, state);
        if (state.dust.balance(new Date()) === 0n) await waitForSpendableDust(facade);
      });
      console.error(`verified ${name} wallet in ${Date.now() - startedAt}ms`);
    }),
  );
}
