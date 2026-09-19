// The connected client context every flow takes: resolved configuration +
// the vault providers + the JOINED vault contract handle. Built once per
// flow file (inside a synced wallet session — see
// {@link file://./vault-session.ts createVaultSession}) and handed to the
// flow functions. The pieces come from where they belong: generic wallet
// construction from the harness session, the contract's types and witnesses
// from its own package, and the provider set + compiled-contract binding from
// the example's deploy package, which its deploy flows build on too.

import { findDeployedContract } from "@midnight-ntwrk/midnight-js/contracts";
// midnight-js reads a process-global network id (unlike compact-js, which
// takes it explicitly). createVaultContext sets it once per construction.
import { setNetworkId } from "@midnight-ntwrk/midnight-js/network-id";
import {
  signetEventSourceFromPublicDataProvider,
  SignetRequestResponseReader,
} from "@sig-net/midnight";
import { getMidnightNodeConfig, type MidnightNodeConfig } from "@sig-net/midnight-contract-deploy";
import { createVaultPrivateState, VAULT_REQUESTS_PATH } from "../contract/src/index.ts";
import {
  type DeployedVaultContract,
  VAULT_PRIVATE_STATE_ID,
  type VaultProviders,
} from "../contract/src/index.ts";
import { buildVaultProviders } from "../deploy/vault-providers.ts";
import { vaultCompiledContract } from "../deploy/vault-contract-binding.ts";
import type { ProofServerObserver } from "../lib/midnight-providers.ts";
import { requireEnv } from "../test-harness/e2e-env.ts";
import type { SessionWallet } from "../test-harness/session.ts";

import { resolveUserIdentity, type UserIdentity } from "./vault-identity.ts";

/**
 * Everything a flow needs: the resolved configuration (all fields REQUIRED —
 * the setup pipeline populates every one before a flow runs), the vault's
 * midnight-js providers, and the joined vault contract. Flows receive this
 * instead of raw env; they never construct providers, wallets, or contract
 * handles themselves.
 */
export interface VaultContext {
  /** Endpoints + network id of the Midnight network in use. */
  readonly nodeConfig: MidnightNodeConfig;
  /** Address of the deployed ERC20 vault contract on Midnight. */
  readonly vaultContractAddress: string;
  /** Address of the deployed central signet contract on Midnight. */
  readonly signetContractAddress: string;
  /** JSON-RPC endpoint of the EVM chain the vault operates on. */
  readonly evmRpcUrl: string;
  /** Chain id of that EVM chain. */
  readonly evmChainId: bigint;
  /** Address of the ERC20 token the vault holds (20-byte 0x hex). */
  readonly erc20Address: string;
  /** The vault's derived EVM account (path "vault") — the withdraw tx sender. */
  readonly evmVaultAddress: string;
  /** The user's derived EVM account (path = identity commitment hex) — the sweep tx sender. */
  readonly evmUserAddress: string;
  /** The caller identity every vault interaction is bound to. */
  readonly identity: UserIdentity;
  /** The vault's provider set (public data / proof / zk-config / private state / wallet). */
  readonly providers: VaultProviders;
  /** The vault at `MIDNIGHT_VAULT_CONTRACT_ADDRESS`, joined with witnesses + the identity as private state. */
  readonly vault: DeployedVaultContract;
}

/**
 * Build the {@link VaultContext}: resolve the configuration from the
 * setup-populated env accumulator, set the midnight-js network id, build the
 * vault's providers around the wallet, and join the deployed vault contract
 * with the user identity as private state.
 *
 * @param env - The setup-populated env accumulator.
 * @param wallet - The started wallet (from the harness session's `wallet()`).
 * @param proofObserver - Called after every proof-server /check and /prove round trip.
 * @returns The context to hand to the flow functions.
 * @throws {Error} If a required env value is missing/malformed or no contract answers
 *   at `MIDNIGHT_VAULT_CONTRACT_ADDRESS`.
 */
export async function createVaultContext(
  env: NodeJS.ProcessEnv,
  wallet: SessionWallet,
  proofObserver?: ProofServerObserver,
): Promise<VaultContext> {
  const nodeConfig = getMidnightNodeConfig(env);
  setNetworkId(nodeConfig.networkId);

  const evmChainIdRaw = requireEnv(env, "EVM_CHAIN_ID");
  if (!/^\d+$/.test(evmChainIdRaw)) {
    throw new Error(`EVM_CHAIN_ID must be a positive integer; got "${evmChainIdRaw}".`);
  }
  const evmChainId = BigInt(evmChainIdRaw);

  const erc20Address = requireEnv(env, "ERC20_ADDRESS");
  if (!/^0x[0-9a-fA-F]{40}$/.test(erc20Address)) {
    throw new Error(`ERC20_ADDRESS must be a 20-byte 0x hex address; got "${erc20Address}".`);
  }

  const vaultContractAddress = requireEnv(env, "MIDNIGHT_VAULT_CONTRACT_ADDRESS");
  const identity = resolveUserIdentity(env);
  const providers = buildVaultProviders(wallet.facade, wallet.keys, nodeConfig, proofObserver);

  const vault = await findDeployedContract(providers, {
    contractAddress: vaultContractAddress,
    compiledContract: vaultCompiledContract,
    privateStateId: VAULT_PRIVATE_STATE_ID,
    initialPrivateState: createVaultPrivateState(identity.secretKey),
  });

  return {
    nodeConfig,
    vaultContractAddress,
    signetContractAddress: requireEnv(env, "MIDNIGHT_SIGNET_CONTRACT_ADDRESS"),
    evmRpcUrl: requireEnv(env, "EVM_RPC_URL"),
    evmChainId,
    erc20Address,
    evmVaultAddress: requireEnv(env, "EVM_VAULT_ADDRESS"),
    evmUserAddress: requireEnv(env, "EVM_USER_ADDRESS"),
    identity,
    providers,
    vault,
  };
}

/**
 * A request/response reader over the context's vault (requester) / signet
 * contract pair, reading through the context's indexer-backed public data
 * provider — the same read path the response server uses. Built fresh per
 * flow invocation (the reader caches fetched request records internally).
 *
 * @param context - The flow's context.
 * @param requestsPath - The resolved ledger-tree path of the request map.
 *   Defaults to VAULT_REQUESTS_PATH ([0, 0], the signBidirectionalEventMap the
 *   approves and withdraw share); deposits pass VAULT_DEPOSIT_REQUESTS_PATH
 *   ([1, 3], the depositEventMap), swaps VAULT_SWAP_REQUESTS_PATH ([1, 7], the
 *   swapEventMap), supply and redeem their own maps' exported paths.
 * @returns The reader.
 */
export function createResponseReader(
  context: VaultContext,
  requestsPath: readonly number[] = VAULT_REQUESTS_PATH,
): SignetRequestResponseReader {
  return new SignetRequestResponseReader({
    requesterContractAddress: context.vaultContractAddress,
    // The requestsPath the vault's notifications pack (erc20-vault.compact).
    // The vault's 20 ledger fields chunk the state tree, so every path is depth 2.
    requesterRequestsPath: requestsPath,
    signetContractAddress: context.signetContractAddress,
    publicDataProvider: context.providers.publicDataProvider,
    // The MPC's responses are read from the contract events the signet
    // contract emits, through the same provider.
    eventSource: signetEventSourceFromPublicDataProvider(context.providers.publicDataProvider),
  });
}
