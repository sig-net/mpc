import {
  type AccountKeys,
  dustShortfall,
  ensureFeeReady,
  formatDust,
  type NetworkId,
  type WalletFacade,
} from "@sig-net/midnight-contract-deploy";

import { withOperationProgress } from "./operation-progress.ts";

/**
 * Wait until the wallet can estimate the complete fee using its spendable coins.
 * The estimator selects DUST inputs and can reject before it can price their balancing cost.
 *
 * @param facade - Started wallet facade.
 * @param keys - Keys of the fee payer.
 * @param networkId - Network used for funding addresses.
 * @param transaction - Actual transaction whose fee will be paid.
 * @param expires - Transaction expiry, including the earliest intent expiry.
 * @param label - Operation and public correlation identifier.
 * @returns Estimated fee including balancing, in SPECKs.
 * @throws {Error} If estimation fails or funding exceeds the validity window.
 */
export async function ensureTransactionFee(
  facade: WalletFacade,
  keys: AccountKeys,
  networkId: NetworkId,
  transaction: Parameters<WalletFacade["estimateTransactionFee"]>[0],
  expires: number,
  label: string,
): Promise<bigint> {
  // Leave one minute for signing, finalisation and submission.
  const deadline: number = expires - 60_000;
  if (Date.now() >= deadline)
    throw new Error(`${label}: insufficient validity time for fee preparation`);
  return withOperationProgress(
    `${label} fee readiness`,
    async (): Promise<bigint> => {
      const floor: bigint = await facade.calculateTransactionFee(transaction);
      const state = await facade.waitForSyncedState();
      const available: bigint = state.dust.balance(new Date());
      console.log(
        `${label}: fee floor ${formatDust(floor)} DUST excluding balancing, available ${formatDust(available)} DUST, shortfall ${formatDust(floor > available ? floor - available : 0n)} DUST`,
      );
      if (available < floor) {
        await ensureFeeReady(
          facade,
          keys,
          state,
          networkId,
          undefined,
          floor,
          Math.max(0, deadline - Date.now()),
        );
      }
      for (;;) {
        if (Date.now() >= deadline)
          throw new Error(`${label}: fee preparation exhausted the transaction validity window`);
        try {
          const fee: bigint = await facade.estimateTransactionFee(transaction, keys.dustSecretKey, {
            ttl: new Date(expires),
          });
          const synced = await facade.waitForSyncedState();
          const balance: bigint = synced.dust.balance(new Date());
          console.log(
            `${label}: estimated ${formatDust(fee)} DUST including balancing, available ${formatDust(balance)} DUST, shortfall ${formatDust(fee > balance ? fee - balance : 0n)} DUST`,
          );
          if (balance < fee) {
            await ensureFeeReady(
              facade,
              keys,
              synced,
              networkId,
              undefined,
              fee,
              Math.max(0, deadline - Date.now()),
            );
            continue;
          }
          if (Date.now() >= deadline)
            throw new Error(`${label}: fee estimate exceeded the transaction validity window`);
          console.log(`${label}: sufficient DUST, funding skipped`);
          return fee;
        } catch (error) {
          const shortfall = dustShortfall(error);
          if (shortfall === undefined && !String(error).includes("could not balance dust"))
            throw error;
          const synced = await facade.waitForSyncedState();
          const night: bigint = Object.values(synced.unshielded.balances).reduce(
            (sum: bigint, value: bigint): bigint => sum + value,
            0n,
          );
          if (night === 0n)
            throw new Error(
              `${label}: insufficient DUST for balancing and no NIGHT to generate more`,
              { cause: error },
            );
          await ensureFeeReady(
            facade,
            keys,
            synced,
            networkId,
            undefined,
            shortfall?.need ?? floor,
            Math.max(0, deadline - Date.now()),
          );
          await new Promise<void>((resolve) =>
            setTimeout(resolve, Math.min(3_000, Math.max(0, deadline - Date.now()))),
          );
        }
      }
    },
    deadline,
  );
}
