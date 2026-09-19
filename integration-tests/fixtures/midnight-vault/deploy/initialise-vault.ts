// `initialise`: the deployer's one-off call sealing the vault's post-deploy
// configuration into the contract: the vault's own EVM address, the EVM chain
// it operates on, the contracts it trades and lends through, and the MPC
// RESPONSE key. The EVM address and the response key both derive from the
// vault's own contract address, so neither can be a constructor argument.
// The circuit gates the call on the deployer identity sealed at deploy time,
// which is what stops anyone else pointing a fresh vault at their own address.

import { findDeployedContract } from "@midnight-ntwrk/midnight-js/contracts";
// midnight-js reads a process-global network id (unlike compact-js, which
// takes it explicitly), so joining a deployed contract needs it set.
import { setNetworkId } from "@midnight-ntwrk/midnight-js/network-id";
import type { PublicDataProvider } from "@midnight-ntwrk/midnight-js/types";
import {
  deriveMidnightResponseKey,
  formatSecp256k1PublicKey,
  parseSecp256k1PublicKey,
} from "@sig-net/midnight";
import {
  deriveAccountKeys,
  ensureFeeReady,
  envOrUndefined,
  getDeployConfig,
  getFaucetUrl,
  parseIdentitySecretKey,
  resolveMpcRootPublicKey,
  withSyncedWalletFacade,
} from "@sig-net/midnight-contract-deploy";
import {
  createVaultPrivateState,
  type DeployedVaultContract,
  deriveVaultEvmAddress,
  evmAddressBytes,
  readVaultLedger,
  VAULT_PRIVATE_STATE_ID,
} from "../contract/src/index.ts";
import { getEvmChainId } from "../lib/evm.ts";

import { resolveEvmTargets, type VaultEvmTargets } from "./evm-targets.ts";
import { vaultCompiledContract } from "./vault-contract-binding.ts";
import { buildVaultProviders } from "./vault-providers.ts";

/** What an {@link initialiseVaultContract} call did. */
export enum InitialiseVaultOutcome {
  /** The initialise circuit ran and sealed the configuration in this call. */
  Initialised = "initialised",
  /** The ledger already reported the vault initialised, so nothing was submitted. */
  AlreadyInitialised = "already-initialised",
}

/** Every argument the vault's `initialise` circuit takes, fully resolved. */
export interface VaultInitialiseConfig {
  /** The vault's own derived EVM account (20-byte 0x hex), the sender of its EVM transactions. */
  readonly vaultEvmAddress: string;
  /** The Uniswap SwapRouter02 the swap circuits call. */
  readonly routerAddress: string;
  /** The Aave underlying token the supply circuit lends. */
  readonly stataUnderlyingAddress: string;
  /** The ERC-4626 wrapper the supply/redeem circuits mint and burn. */
  readonly stataTokenAddress: string;
  /** EIP-155 chain id of the Ethereum network the vault's transactions are signed for. */
  readonly evmChainId: bigint;
  /**
   * The MPC response key for THIS vault contract (SEC1 hex): `f(MPC root key,
   * vault contract address, "midnight response key")`. The claim and
   * completeWithdraw circuits accept only responses ECDSA-signed by it.
   */
  readonly mpcResponseKey: string;
}

// A required environment value, with a message naming what produces it.
function requireValue(
  env: Record<string, string | undefined>,
  name: string,
  produces: string,
): string {
  const value = envOrUndefined(env, name);
  if (!value) throw new Error(`${name} is required to initialise the vault: ${produces}`);
  return value;
}

// Guard a value the caller may have pinned in the environment against the value
// derived here. A mismatch means the environment and the contract about to be
// initialised disagree, which would seal an address nothing can sign for.
function assertDerivedMatch(preset: string | undefined, derived: string, name: string): void {
  if (preset && preset.toLowerCase() !== derived.toLowerCase()) {
    throw new Error(
      `${name} is set to ${preset}, but the vault contract derives ${derived}. ` +
        "Unset it, or point it at the contract it belongs to.",
    );
  }
}

// The EIP-155 chain id sealed at initialise, which every signed vault
// transaction carries: `EVM_CHAIN_ID` when set, read from `EVM_RPC_URL` when
// not, and checked against the chain when both are set.
async function resolveEvmChainId(env: Record<string, string | undefined>): Promise<bigint> {
  const preset = envOrUndefined(env, "EVM_CHAIN_ID");
  if (preset !== undefined && !/^[1-9]\d*$/.test(preset)) {
    throw new Error(
      `EVM_CHAIN_ID must be a positive integer with no leading zeros, got "${preset}".`,
    );
  }
  const rpcUrl = envOrUndefined(env, "EVM_RPC_URL");
  if (rpcUrl === undefined) {
    if (preset === undefined) {
      throw new Error(
        "EVM_CHAIN_ID or EVM_RPC_URL is required to initialise the vault: the chain id pins " +
          "the chain the vault's EVM transactions target, and the RPC lets it be read from " +
          "that chain.",
      );
    }
    return BigInt(preset);
  }
  let reported: bigint;
  try {
    reported = await getEvmChainId(rpcUrl);
  } catch (error) {
    throw new Error(`EVM_RPC_URL (${rpcUrl}) is not answering, so the chain id cannot be read`, {
      cause: error,
    });
  }
  if (preset !== undefined && BigInt(preset) !== reported) {
    throw new Error(
      `EVM_CHAIN_ID (${preset}) must match the chain EVM_RPC_URL serves, which reports ` +
        `${String(reported)}: the id is sealed into the vault at initialise.`,
    );
  }
  return reported;
}

// Everything initialise needs that does NOT depend on the vault's own address,
// fully validated. Split out so a caller can fail on a missing or malformed
// value BEFORE deploying the contract those values would configure.
async function resolveAddressFreeInputs(env: Record<string, string | undefined>): Promise<{
  mpcSecp256k1PublicKey: string;
  evmChainId: bigint;
  targets: VaultEvmTargets;
}> {
  // The SDK's published key for a deployed network, or MPC_SECP256K1_PUBKEY in
  // any spelling, canonicalised so the derivations below read one form.
  const mpcSecp256k1PublicKey = resolveMpcRootPublicKey(env).value;
  const evmChainId = await resolveEvmChainId(env);

  // Parse the targets up front: a malformed override must fail before
  // anything is submitted, not mid-initialise.
  const targets = resolveEvmTargets(env);
  evmAddressBytes(targets.routerAddress);
  evmAddressBytes(targets.stataUnderlyingAddress);
  evmAddressBytes(targets.stataTokenAddress);

  return { mpcSecp256k1PublicKey, evmChainId, targets };
}

/**
 * Resolve every `initialise` argument for the vault at `vaultContractAddress`.
 * The vault's EVM address and MPC response key are DERIVED from the MPC's
 * secp256k1 public key plus that contract address, so a fresh deploy needs no
 * new configuration. Values already pinned in the environment are verified
 * against the derivation, since a stale pin would seal an
 * account the MPC never signs from.
 *
 * @param env - The environment providing `EVM_CHAIN_ID` or `EVM_RPC_URL` (the chain to
 *   seal, read from the RPC when the id is unset and checked against it when both are set),
 *   `MPC_SECP256K1_PUBKEY` where the SDK publishes no MPC root public key for the
 *   network (see `resolveMpcRootPublicKey`), and the optional `EVM_ROUTER` /
 *   `EVM_STATA_UNDERLYING` / `EVM_STATA_TOKEN` overrides.
 * @param vaultContractAddress - The deployed vault contract's address.
 * @returns The resolved arguments.
 * @throws {Error} If no MPC root public key or chain id resolves, `MPC_SECP256K1_PUBKEY` is
 *   not a secp256k1 public key, `EVM_CHAIN_ID` is malformed or contradicts the RPC, or a
 *   preset `EVM_VAULT_ADDRESS` / `MPC_RESPONSE_KEY` contradicts the derivation.
 */
export async function resolveInitialiseConfig(
  env: Record<string, string | undefined>,
  vaultContractAddress: string,
): Promise<VaultInitialiseConfig> {
  const { mpcSecp256k1PublicKey, evmChainId, targets } = await resolveAddressFreeInputs(env);

  const vaultEvmAddress = deriveVaultEvmAddress(mpcSecp256k1PublicKey, vaultContractAddress);
  assertDerivedMatch(
    envOrUndefined(env, "EVM_VAULT_ADDRESS"),
    vaultEvmAddress,
    "EVM_VAULT_ADDRESS",
  );

  const mpcResponseKey = formatSecp256k1PublicKey(
    deriveMidnightResponseKey(mpcSecp256k1PublicKey, vaultContractAddress),
  );
  assertDerivedMatch(envOrUndefined(env, "MPC_RESPONSE_KEY"), mpcResponseKey, "MPC_RESPONSE_KEY");

  return {
    vaultEvmAddress,
    ...targets,
    evmChainId,
    mpcResponseKey,
  };
}

/**
 * Fail now on anything `initialise` needs that does NOT depend on the vault's
 * address, so a deploy+initialise run cannot spend a full multistage deploy and
 * only then discover a missing chain id or a malformed router address, leaving
 * a deployed vault stranded uninitialised.
 *
 * @param env - The environment the subsequent {@link resolveInitialiseConfig} will read.
 * @throws {Error} If a required variable is missing or malformed.
 */
export async function assertInitialiseInputsPresent(
  env: Record<string, string | undefined>,
): Promise<void> {
  await resolveAddressFreeInputs(env);
}

// The values that belong to ONE vault contract: its address and the two
// derived from it. A fresh deploy mints a new address, so any of these already
// in the environment belongs to a previous vault.
const VAULT_BOUND_KEYS = [
  "MIDNIGHT_VAULT_CONTRACT_ADDRESS",
  "EVM_VAULT_ADDRESS",
  "MPC_RESPONSE_KEY",
] as const;

/**
 * Refuse a deploy+initialise run whose environment already carries a vault
 * address or a value derived from one. {@link resolveInitialiseConfig} checks
 * a preset against the derivation, but that derivation needs the new address,
 * so it can only run after the deploy: a stale preset would pass every
 * pre-deploy check and fail initialise, stranding the fresh vault. Before the
 * deploy the presence of such a value is itself the defect.
 *
 * @param env - The environment the deploy and initialise will read.
 * @throws {Error} If any of `MIDNIGHT_VAULT_CONTRACT_ADDRESS`, `EVM_VAULT_ADDRESS` or
 *   `MPC_RESPONSE_KEY` is set.
 */
export function assertNoVaultBoundPresets(env: Record<string, string | undefined>): void {
  const stale = VAULT_BOUND_KEYS.filter((key) => envOrUndefined(env, key) !== undefined);
  if (stale.length === 0) return;
  throw new Error(
    `${stale.join(", ")} ${stale.length === 1 ? "is" : "are"} set, but a fresh deploy mints a new vault ` +
      "address that these values derive from, so they belong to a previous vault. Unset them to " +
      "deploy a new vault, or run `yarn initialise:erc20-vault` to initialise the one they name.",
  );
}

/**
 * Run the vault's one-shot `initialise` circuit, skipping when the ledger
 * already reports the vault initialised (so a rerun against a kept contract
 * address is a no-op rather than a circuit failure).
 *
 * The caller must hold the DEPLOYER identity: the circuit compares the
 * `callerSecretKey` witness commitment against the sealed `deployer` field.
 *
 * @param vault - The joined vault contract handle.
 * @param publicDataProvider - The provider to read the vault's current ledger state through.
 * @param vaultContractAddress - The vault contract's address (the state to read).
 * @param config - The resolved circuit arguments, from {@link resolveInitialiseConfig}.
 * @returns Whether this call initialised the vault or found it already initialised.
 * @throws {Error} If an argument is malformed or the circuit rejects the caller.
 */
export async function initialiseVaultContract(
  vault: DeployedVaultContract,
  publicDataProvider: PublicDataProvider,
  vaultContractAddress: string,
  config: VaultInitialiseConfig,
): Promise<InitialiseVaultOutcome> {
  if ((await readVaultLedger(publicDataProvider, vaultContractAddress)).initialised) {
    console.log("vault is already initialised, skipping initialise");
    return InitialiseVaultOutcome.AlreadyInitialised;
  }

  console.log(`vault contract:    ${vaultContractAddress}`);
  console.log(`vault EVM address: ${config.vaultEvmAddress}`);
  console.log(`router:            ${config.routerAddress}`);
  console.log(`stata pair:        ${config.stataUnderlyingAddress} -> ${config.stataTokenAddress}`);
  console.log(`EVM chain id:      ${String(config.evmChainId)}`);
  console.log(`MPC response key:  ${config.mpcResponseKey}`);

  const result = await vault.callTx.initialise(
    evmAddressBytes(config.vaultEvmAddress),
    evmAddressBytes(config.routerAddress),
    evmAddressBytes(config.stataUnderlyingAddress),
    evmAddressBytes(config.stataTokenAddress),
    config.evmChainId,
    parseSecp256k1PublicKey(config.mpcResponseKey),
  );
  console.log(`initialise finalized in tx ${result.public.txId}`);
  return InitialiseVaultOutcome.Initialised;
}

/**
 * Join a deployed vault as the deployer and initialise it: the standalone
 * counterpart of {@link initialiseVaultContract} for entrypoints that hold no
 * session. The deployer identity resolves exactly as the deploy resolves it
 * (`VAULT_DEPLOYER_SECRET_KEY`, falling back to the `DEPLOYER_SEED` bytes), so
 * the caller and the commitment sealed at deploy agree by construction.
 *
 * @param env - The environment: the deploy SDK's Midnight node configuration, `DEPLOYER_SEED`,
 *   `VAULT_DEPLOYER_SECRET_KEY`, and everything {@link resolveInitialiseConfig} reads.
 *   Defaults to `process.env`.
 * @param contractAddress - The vault to initialise. Defaults to `MIDNIGHT_VAULT_CONTRACT_ADDRESS`.
 * @returns Whether this call initialised the vault or found it already initialised.
 * @throws {WalletUnfundedError} If the deployer wallet holds neither NIGHT nor
 *   DUST: the error carries the wallet's NIGHT receive address to fund.
 * @throws {Error} If no contract address is available, a required variable is missing,
 *   no spendable DUST appears after registering the wallet's NIGHT, no contract
 *   answers at the address, or the circuit rejects the caller.
 */
export async function initialiseVault(
  env: Record<string, string | undefined> = process.env,
  contractAddress?: string,
): Promise<InitialiseVaultOutcome> {
  // A blank explicit address is treated as absent, so a caller threading an
  // unset value through still gets the environment's answer (or its error).
  const explicitAddress = contractAddress?.trim();
  const vaultContractAddress =
    explicitAddress === undefined || explicitAddress === ""
      ? requireValue(
          env,
          "MIDNIGHT_VAULT_CONTRACT_ADDRESS",
          "it names the vault to initialise (the deploy prints it)",
        )
      : explicitAddress;

  const deployConfig = getDeployConfig(env);
  const nodeConfig = deployConfig.midnightNodeConfig;
  setNetworkId(nodeConfig.networkId);

  // Resolve the arguments before starting a wallet: a missing variable or a
  // preset contradicting the derivation should fail here, not after a sync.
  const config = await resolveInitialiseConfig(env, vaultContractAddress);

  const secretKey = parseIdentitySecretKey(
    "VAULT_DEPLOYER_SECRET_KEY",
    env,
    deployConfig.deployerSeed,
  );
  const accountKeys = deriveAccountKeys(deployConfig.deployerSeed, nodeConfig.networkId);

  return withSyncedWalletFacade(accountKeys, nodeConfig, async (facade, state) => {
    await ensureFeeReady(
      facade,
      accountKeys,
      state,
      nodeConfig.networkId,
      getFaucetUrl(env, nodeConfig.networkId),
    );
    const providers = buildVaultProviders(facade, accountKeys, nodeConfig);
    const vault = await findDeployedContract(providers, {
      contractAddress: vaultContractAddress,
      compiledContract: vaultCompiledContract,
      privateStateId: VAULT_PRIVATE_STATE_ID,
      initialPrivateState: createVaultPrivateState(secretKey),
    });
    return initialiseVaultContract(
      vault,
      providers.publicDataProvider,
      vaultContractAddress,
      config,
    );
  });
}
