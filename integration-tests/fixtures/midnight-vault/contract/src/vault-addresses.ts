// The published per-network erc20-vault contract addresses. The vault's other
// counterparty values all derive from an entry here: the vault's EVM account
// via `deriveVaultEvmAddress` and the MPC response key via
// `deriveMidnightResponseKey`, each taking the network's MPC root public key
// (published in @sig-net/midnight) plus this contract address. Publishing only
// the address keeps a single source those derivations cannot drift from.

import { type DeployedNetwork, MidnightNetwork } from "@sig-net/midnight";

// Filled in per network by the erc20-vault-deploy workflow's record-address
// PR (the deploy package's record-contract-address entrypoint rewrites one
// entry). An empty string means "not yet deployed or published" and makes
// getVaultContractAddress throw for that network.
const vaultContractAddresses: Record<DeployedNetwork, string> = {
  [MidnightNetwork.Stagenet]: "5fa9de7119edcab960b9a9cc2772efc7018664a6ddb256372ad4a57eb121d3f4",
  [MidnightNetwork.Preview]: "",
  [MidnightNetwork.Preprod]: "",
  [MidnightNetwork.Mainnet]: "",
};

/**
 * The address of the deployed erc20-vault contract on a deployed Midnight
 * network: the `contractAddress` a client joins with `findDeployedContract`.
 * The local standalone stack has no fixed address: each e2e run deploys its
 * own vault.
 *
 * @param networkId - The deployed network to look up.
 * @returns The network's vault contract address.
 * @throws {Error} When no vault address is published for that network yet.
 */
export function getVaultContractAddress(networkId: DeployedNetwork): string {
  const contractAddress = vaultContractAddresses[networkId];
  if (!contractAddress) {
    throw new Error(`no erc20-vault contract address published for the '${networkId}' network yet`);
  }
  return contractAddress;
}
