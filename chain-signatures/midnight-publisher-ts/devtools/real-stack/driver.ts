import { Transaction, hexlify, recoverAddress } from "ethers";
import { createInterface } from "node:readline";
import { join } from "node:path";
import { findDeployedContract, type FoundContract } from "@midnight-ntwrk/midnight-js/contracts";
import { setNetworkId } from "@midnight-ntwrk/midnight-js/network-id";
import {
  buildDeployTransaction,
  deploySignetContract,
  deriveAccountKeys,
  deriveWalletAddresses,
  GENESIS_MINT_WALLET_SEED,
  initialiseWalletFacade,
  isLocalStandaloneNetwork,
  registerNightForDustGeneration,
  submitUnprovenTransaction,
  transferNight,
  waitForSpendableDust,
  withSyncedWalletFacade,
  type FacadeState,
  type MidnightNodeConfig,
  type WalletFacade,
} from "@sig-net/midnight-contract-deploy";
import {
  contractAddressFromHex,
  assembleCalldata,
  signatureRespondedEventToSignature,
  parseRequestIdHex,
  parseSecp256k1PublicKey,
  requestIdBytes,
  respondBidirectionalEventToCircuitInput,
  signetEventSourceFromIndexer,
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
  outputType: "bool" | "uint64" | "bytes32";
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
  rejectPaddedReplay?: boolean;
}

interface NotifyAsCallerRequest {
  op: "notifyAsCaller";
  requestId: string;
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
  | NotifyAsCallerRequest
  | ShutdownRequest;

interface Session {
  facade: WalletFacade;
  caller: CallerHandle;
  callerAddress: string;
  impersonator: CallerHandle;
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

function totalNight(state: FacadeState): bigint {
  return Object.values(state.unshielded.balances).reduce((sum, value) => sum + value, 0n);
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

// Mirrors the package's per-child flow but amortizes the expensive part: a
// root facade re-syncs from genesis once (that re-sync dominates wall time),
// funds every role wallet sequentially from that live facade, and the
// independent child verifications run concurrently afterwards.
async function fundRoles(config: MidnightNodeConfig): Promise<void> {
  const networkId = config.networkId;
  const rootKeys = deriveAccountKeys(GENESIS_MINT_WALLET_SEED, networkId);
  const roles = [
    ["deployer", DEPLOYER_SEED],
    ["invoker", INVOKER_SEED],
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
    if (state.dust.balance(new Date()) === 0n) await waitForSpendableDust(rootFacade, 1n);

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
          diagnostics(
            `root DUST is not yet enough to cover the ${name} transfer; retrying (attempt ${attempt + 1})`,
          );
          await sleep(5_000);
          state = await rootFacade.waitForSyncedState();
        }
      }
      // Let the transfer block land before selecting UTXOs for the next one.
      await sleep(3_000);
      state = await rootFacade.waitForSyncedState();
      diagnostics(`funded ${name} wallet in ${Date.now() - startedAt}ms`);
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
        if (state.dust.balance(new Date()) === 0n) await waitForSpendableDust(facade, 1n);
      });
      diagnostics(`verified ${name} wallet in ${Date.now() - startedAt}ms`);
    }),
  );
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
  const deployCaller = () =>
    withSyncedWalletFacade(deployerKeys, request.config, async (facade) => {
      const built = await buildDeployTransaction(
        callerCompiledContract,
        request.config.networkId,
        deployerKeys.shieldedSecretKeys.coinPublicKey,
        createCallerPrivateState(deployerSecret),
        deployerCommitment,
        contractAddressFromHex(central.contractAddress),
      );
      await submitUnprovenTransaction(facade, deployerKeys, built.serializedTransaction);
      return { contractAddress: built.contractAddress };
    });
  const callerDeployment = await deployCaller();
  diagnostics("deploying impersonating Compact caller");
  const impersonatorDeployment = await deployCaller();
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
  const findCaller = (contractAddress: string) =>
    findDeployedContract(providers, {
      contractAddress,
      compiledContract: callerCompiledContract,
      privateStateId: CALLER_PRIVATE_STATE_ID,
      initialPrivateState: createCallerPrivateState(deployerSecret),
    });
  const caller = await findCaller(callerDeployment.contractAddress);
  const impersonator = await findCaller(impersonatorDeployment.contractAddress);
  session = {
    facade,
    caller,
    callerAddress: callerDeployment.contractAddress,
    impersonator,
    publicDataProvider: providers.publicDataProvider,
    reader: new SignetRequestResponseReader({
      requesterContractAddress: callerDeployment.contractAddress,
      requesterRequestsPath: [2],
      signetContractAddress: central.contractAddress,
      publicDataProvider: providers.publicDataProvider,
      eventSource: signetEventSourceFromIndexer({ queryUrl: request.config.indexerUrl }),
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
  if (request.op === "notifyAsCaller") {
    const requestId = parseRequestIdHex(request.requestId);
    await active.impersonator.callTx.notifyAs(
      contractAddressFromHex(active.callerAddress),
      requestIdBytes(requestId),
    );
    return {};
  }
  if (request.op === "signedTransaction") {
    const requestId = parseRequestIdHex(request.requestId);
    const state = await active.publicDataProvider.queryContractState(active.callerAddress);
    if (!state) throw new Error("caller state is missing");
    const record = ledger(state.data).requests.lookup(requestIdBytes(requestId));
    const params = record.txParams;
    if (params.nonce > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("unsafe EVM nonce");
    const unsigned = Transaction.from({
      type: 2,
      chainId: params.chainId,
      nonce: Number(params.nonce),
      maxPriorityFeePerGas: params.maxPriorityFeePerGas,
      maxFeePerGas: params.maxFeePerGas,
      gasLimit: params.gasLimit,
      to: hexlify(params.to),
      value: params.value,
      data: assembleCalldata(params.calldata),
      accessList: params.accessList.slice(0, Number(params.accessListEntryCount)).map((entry) => ({
        address: hexlify(entry.address),
        storageKeys: entry.storageKeys.slice(0, Number(entry.storageKeyCount)).map(hexlify),
      })),
    });
    const transaction = await waitFor("a verified signed EVM transaction", async () => {
      for (const response of await active.reader.getSignatureRespondedEvents(requestId)) {
        try {
          const signature = signatureRespondedEventToSignature(response);
          if (
            recoverAddress(unsigned.unsignedHash, signature).toLowerCase() !==
            request.expectedSigner.toLowerCase()
          )
            continue;
          const signed = unsigned.clone();
          signed.signature = signature;
          return signed;
        } catch {
          // Response logs are unauthenticated; skip malformed posts.
        }
      }
      return undefined;
    });
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
    const check =
      serializedOutput.length === 0
        ? pureCircuits.checkResponse0
        : serializedOutput.length === 1
          ? pureCircuits.checkResponse1
          : serializedOutput.length === 8
            ? pureCircuits.checkResponse8
            : serializedOutput.length === 32
              ? pureCircuits.checkResponse32
              : undefined;
    if (check === undefined) throw new Error(`unsupported output width ${serializedOutput.length}`);
    const response = await waitFor("a verified respondBidirectional entry", async () => {
      for (const candidate of await active.reader.getRespondBidirectionalEvents(requestId)) {
        try {
          if (
            check(respondBidirectionalEventToCircuitInput(candidate), serializedOutput, responseKey)
          )
            return candidate;
        } catch {
          // Response logs are unauthenticated; skip malformed posts.
        }
      }
      return undefined;
    });
    const circuitInput = respondBidirectionalEventToCircuitInput(response);
    if (request.rejectPaddedReplay === true) {
      const padded = new Uint8Array(8);
      padded.set(serializedOutput);
      if (pureCircuits.checkResponse8({ ...circuitInput, outputKind: 0 }, padded, responseKey))
        throw new Error("accepted a padded failure as an executed outcome");
      let rejected = false;
      try {
        await active.caller.callTx.verifyResponse8({ ...circuitInput, outputKind: 0 }, padded);
      } catch (error) {
        if (!String(error).includes("Invalid attestation signature")) throw error;
        rejected = true;
      }
      if (!rejected) throw new Error("Compact accepted a padded failure as an executed outcome");
      if (!(await callerHasRequest(active, requestId)))
        throw new Error("replay consumed the pending request");
    }
    const verify =
      serializedOutput.length === 0
        ? active.caller.callTx.verifyResponse0
        : serializedOutput.length === 1
          ? active.caller.callTx.verifyResponse
          : serializedOutput.length === 8
            ? active.caller.callTx.verifyResponse8
            : serializedOutput.length === 32
              ? active.caller.callTx.verifyResponse32
              : undefined;
    if (verify === undefined)
      throw new Error(`unsupported output width ${serializedOutput.length}`);
    await verify(circuitInput, serializedOutput);
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
    new TextEncoder().encode(
      JSON.stringify([{ name: "success", type: request.outputType }]).padEnd(64, " "),
    ),
    new TextEncoder().encode(
      JSON.stringify([{ name: "success", type: request.outputType }]).padEnd(64, " "),
    ),
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
