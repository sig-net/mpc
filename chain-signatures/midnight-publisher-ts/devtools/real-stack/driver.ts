import { createInterface } from "node:readline";
import { join } from "node:path";
import { findDeployedContract, type FoundContract } from "@midnight-ntwrk/midnight-js/contracts";
import { setNetworkId } from "@midnight-ntwrk/midnight-js/network-id";
import {
  assertRootFunded,
  buildDeployTransaction,
  contractAddressToReference,
  deploySignetContract,
  deriveAccountKeys,
  fundChildFromRoot,
  GENESIS_MINT_WALLET_SEED,
  initialiseWalletFacade,
  isFeeReady,
  readAccountFunding,
  submitUnprovenTransaction,
  withSyncedWalletFacade,
  type MidnightNodeConfig,
  type WalletFacade,
} from "@sig-net/midnight-contract-deploy";
import { deriveMidnightResponseKey } from "@sig-net/midnight";
import { pureCircuits, type Contract } from "./managed/caller/contract/index.js";
import {
  buildCallerProviders,
  callerCompiledContract,
  CALLER_PRIVATE_STATE_ID,
} from "./providers.js";
import { createCallerPrivateState, type CallerPrivateState } from "./witnesses.js";

const DEPLOYER_SEED = "02".repeat(32);
const INVOKER_SEED = "03".repeat(32);
const PUBLISHER_SEED = "04".repeat(32);

type CallerHandle = FoundContract<Contract<CallerPrivateState>>;

interface BootstrapRequest {
  op: "bootstrap";
  config: MidnightNodeConfig;
  rootPublicKey: string;
  artifactDir: string;
}

interface SubmitRequest {
  op: "submitIsEven";
  nonce: string;
  target: string;
  argument: string;
}

interface ShutdownRequest {
  op: "shutdown";
}

type Request = BootstrapRequest | SubmitRequest | ShutdownRequest;

interface Session {
  facade: WalletFacade;
  caller: CallerHandle;
}

let session: Session | undefined;

const diagnostics = (...values: unknown[]) => {
  process.stderr.write(`${values.map(String).join(" ")}\n`);
};
console.log = diagnostics;
console.info = diagnostics;
console.warn = diagnostics;

function bytes(hex: string, width?: number): Uint8Array {
  const bare = hex.replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]*$/.test(bare) || bare.length % 2 !== 0) {
    throw new Error(`expected even-length hex, got ${hex}`);
  }
  const result = Uint8Array.from(bare.match(/.{2}/g)?.map((part) => Number.parseInt(part, 16)) ?? []);
  if (width !== undefined && result.length !== width) {
    throw new Error(`expected ${width} bytes, got ${result.length}`);
  }
  return result;
}

function deployEnv(config: MidnightNodeConfig, seed: string): Record<string, string> {
  return {
    NETWORK_ID: config.networkId,
    MIDNIGHT_NODE_URL: config.nodeUrl,
    MIDNIGHT_NODE_INDEXER_URL: config.indexerUrl,
    MIDNIGHT_NODE_INDEXER_WS_URL: config.indexerWsUrl,
    MIDNIGHT_NODE_PROOF_SERVER_URL: config.proofServerUrl,
    DEPLOYER_SEED: seed,
  };
}

async function fundRoles(config: MidnightNodeConfig): Promise<void> {
  const root = await assertRootFunded(config, GENESIS_MINT_WALLET_SEED, undefined);
  const amount = root.night / 5n;
  if (amount === 0n) throw new Error("local genesis wallet cannot fund role wallets");
  for (const seed of [DEPLOYER_SEED, INVOKER_SEED, PUBLISHER_SEED]) {
    const current = await readAccountFunding(config, seed);
    if (!isFeeReady(current)) {
      await fundChildFromRoot(config, GENESIS_MINT_WALLET_SEED, seed, amount);
    }
  }
}

async function bootstrap(request: BootstrapRequest) {
  if (session !== undefined) throw new Error("driver is already bootstrapped");
  setNetworkId(request.config.networkId);
  diagnostics("funding real-stack role wallets");
  await fundRoles(request.config);
  diagnostics("deploying central Signet contract");
  const central = await deploySignetContract(deployEnv(request.config, DEPLOYER_SEED));

  const deployerKeys = deriveAccountKeys(DEPLOYER_SEED, request.config.networkId);
  const deployerSecret = bytes(DEPLOYER_SEED, 32);
  const deployerCommitment = pureCircuits.deployerCommitment(deployerSecret);
  const callerDeployment = await withSyncedWalletFacade(
    deployerKeys,
    request.config,
    async (facade) => {
      const built = await buildDeployTransaction(
        callerCompiledContract,
        request.config.networkId,
        deployerKeys.shieldedSecretKeys.coinPublicKey,
        createCallerPrivateState(deployerSecret),
        deployerCommitment,
        contractAddressToReference(central.contractAddress),
      );
      await submitUnprovenTransaction(
        facade,
        deployerKeys,
        built.serializedTransaction,
      );
      return { contractAddress: built.contractAddress };
    },
  );
  diagnostics("initialising deployed Compact caller");

  const invokerKeys = deriveAccountKeys(INVOKER_SEED, request.config.networkId);
  const facade = await initialiseWalletFacade(invokerKeys, request.config);
  await facade.start(invokerKeys.shieldedSecretKeys, invokerKeys.dustSecretKey);
  await facade.waitForSyncedState();
  const providers = buildCallerProviders(
    facade,
    invokerKeys,
    request.config,
    join(request.artifactDir, "caller.leveldb"),
  );
  const caller = await findDeployedContract(providers, {
    contractAddress: callerDeployment.contractAddress,
    compiledContract: callerCompiledContract,
    privateStateId: CALLER_PRIVATE_STATE_ID,
    initialPrivateState: createCallerPrivateState(deployerSecret),
  });
  const responseKey = deriveMidnightResponseKey(
    request.rootPublicKey,
    callerDeployment.contractAddress,
  );
  await caller.callTx.initialise(responseKey);
  session = {
    facade,
    caller,
  };
  return {
    centralAddress: central.contractAddress,
    publisherSeed: PUBLISHER_SEED,
  };
}

async function dispatch(request: Request): Promise<unknown> {
  if (request.op === "bootstrap") return bootstrap(request);
  if (request.op === "shutdown") {
    await session?.facade.stop();
    session = undefined;
    return {};
  }
  if (session === undefined) throw new Error("driver is not bootstrapped");
  await session.facade.waitForSyncedState();
  await session.caller.callTx.submitIsEvenRequest(
    BigInt(request.nonce),
    1n,
    bytes(request.target, 20),
    bytes(request.argument, 32),
  );
  return {};
}

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  try {
    const result = await dispatch(JSON.parse(line) as Request);
    process.stdout.write(`${JSON.stringify({ ok: true, result })}\n`);
  } catch (error) {
    process.stdout.write(
      `${JSON.stringify({ ok: false, error: error instanceof Error ? error.stack ?? error.message : String(error) })}\n`,
    );
  }
}
await session?.facade.stop().catch(() => undefined);
