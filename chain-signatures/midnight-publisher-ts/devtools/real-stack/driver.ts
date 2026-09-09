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
import {
  parseRequestIdHex,
  parseSecp256k1PublicKey,
  requestIdBytes,
  respondBidirectionalEventToCircuitInput,
  signetEventSourceFromPublicDataProvider,
  SignetRequestResponseReader,
  type RequestIdHex,
  type Secp256k1Point,
  type SignetPublicStateSource,
} from "@sig-net/midnight";
import { ledger, pureCircuits, type Contract } from "./managed/caller/contract/index.js";
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
  artifactDir: string;
}

interface InitialiseRequest {
  op: "initialise";
  responsePublicKey: string;
}

interface SubmitRequest {
  op: "submitIsEven";
  nonce: string;
  target: string;
  argument: string;
}

interface SignedTransactionRequest {
  op: "signedTransaction";
  requestId: string;
  expectedSigner: string;
}

interface SettleResponseRequest {
  op: "settleResponse";
  requestId: string;
  serializedOutput: string;
}

interface ShutdownRequest {
  op: "shutdown";
}

type Request =
  | BootstrapRequest
  | InitialiseRequest
  | SubmitRequest
  | SignedTransactionRequest
  | SettleResponseRequest
  | ShutdownRequest;

interface Session {
  facade: WalletFacade;
  caller: CallerHandle;
  callerAddress: string;
  publicDataProvider: SignetPublicStateSource;
  reader: SignetRequestResponseReader;
  responseKey?: Secp256k1Point;
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
  const result = Uint8Array.from(
    bare.match(/.{2}/g)?.map((part) => Number.parseInt(part, 16)) ?? [],
  );
  if (width !== undefined && result.length !== width) {
    throw new Error(`expected ${width} bytes, got ${result.length}`);
  }
  return result;
}

async function waitFor<T>(description: string, read: () => Promise<T | undefined>): Promise<T> {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const value = await read();
    if (value !== undefined) return value;
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error(`timed out waiting for ${description}`);
}

async function callerHasRequest(active: Session, requestId: RequestIdHex): Promise<boolean> {
  const state = await active.publicDataProvider.queryContractState(active.callerAddress);
  if (!state) throw new Error(`no caller state found at ${active.callerAddress}`);
  return ledger(state.data).requests.member(requestIdBytes(requestId));
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

// `assertRootFunded` returns as soon as root's spendable DUST is positive, but a
// transfer's fee may exceed that first sliver until a few more blocks of DUST
// generate. A transfer built too early fails to balance ("could not balance
// dust"); the same transfer a few blocks later succeeds. Retry only that error,
// so root's DUST can catch up without masking a genuine funding failure.
function isDustBalancingShortfall(error: unknown): boolean {
  const text = error instanceof Error ? `${error.message}\n${error.stack ?? ""}` : String(error);
  return /Wallet\.InsufficientFunds|Insufficient Funds|could not balance dust/i.test(text);
}

async function fundChildWaitingForRootDust(
  config: MidnightNodeConfig,
  childSeed: string,
  amount: bigint,
): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      await fundChildFromRoot(config, GENESIS_MINT_WALLET_SEED, childSeed, amount);
      return;
    } catch (error) {
      if (attempt >= 11 || !isDustBalancingShortfall(error)) throw error;
      diagnostics(
        `root DUST is not yet enough to cover the transfer fee; retrying child funding (attempt ${attempt + 1})`,
      );
      await new Promise((resolve) => setTimeout(resolve, 5_000));
    }
  }
}

async function fundRoles(config: MidnightNodeConfig): Promise<void> {
  const root = await assertRootFunded(config, GENESIS_MINT_WALLET_SEED, undefined);
  const amount = root.night / 5n;
  if (amount === 0n) throw new Error("local genesis wallet cannot fund role wallets");
  for (const seed of [DEPLOYER_SEED, INVOKER_SEED, PUBLISHER_SEED]) {
    const current = await readAccountFunding(config, seed);
    if (!isFeeReady(current)) {
      await fundChildWaitingForRootDust(config, seed, amount);
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
      await submitUnprovenTransaction(facade, deployerKeys, built.serializedTransaction);
      return { contractAddress: built.contractAddress };
    },
  );
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
  session = {
    facade,
    caller,
    callerAddress: callerDeployment.contractAddress,
    publicDataProvider: providers.publicDataProvider,
    reader: new SignetRequestResponseReader({
      requesterContractAddress: callerDeployment.contractAddress,
      requesterRequestsPath: [3],
      signetContractAddress: central.contractAddress,
      publicDataProvider: providers.publicDataProvider,
      eventSource: signetEventSourceFromPublicDataProvider(providers.publicDataProvider),
    }),
  };
  return {
    centralAddress: central.contractAddress,
    callerAddress: callerDeployment.contractAddress,
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
  const active = session;
  await active.facade.waitForSyncedState();
  if (request.op === "initialise") {
    if (active.responseKey !== undefined) throw new Error("caller is already initialised");
    diagnostics("initialising deployed Compact caller");
    const responseKey = parseSecp256k1PublicKey(request.responsePublicKey);
    await active.caller.callTx.initialise(responseKey);
    active.responseKey = responseKey;
    return {};
  }
  if (request.op === "signedTransaction") {
    const requestId = parseRequestIdHex(request.requestId);
    const transaction = await waitFor("a verified signed EVM transaction", () =>
      active.reader.getSignedEvmTransaction(requestId, request.expectedSigner),
    );
    return {
      serialized: transaction.serialized,
      unsignedHash: transaction.unsignedHash,
      from: transaction.from,
      to: transaction.to,
      data: transaction.data,
      chainId: transaction.chainId.toString(),
    };
  }
  if (request.op === "settleResponse") {
    const responseKey = active.responseKey;
    if (responseKey === undefined) throw new Error("caller is not initialised");
    const requestId = parseRequestIdHex(request.requestId);
    const serializedOutput = bytes(request.serializedOutput);
    const response = await waitFor("a verified respondBidirectional entry", () =>
      active.reader.getVerifiedRespondBidirectionalEvent(requestId, serializedOutput, responseKey),
    );
    await active.caller.callTx.verifyResponse(
      requestIdBytes(requestId),
      respondBidirectionalEventToCircuitInput(response),
      serializedOutput,
    );
    await waitFor("the caller request to be removed", async () =>
      (await callerHasRequest(active, requestId)) ? undefined : true,
    );
    return {};
  }
  await active.caller.callTx.submitIsEvenRequest(
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
      `${JSON.stringify({ ok: false, error: error instanceof Error ? (error.stack ?? error.message) : String(error) })}\n`,
    );
  }
}
await session?.facade.stop().catch(() => undefined);
