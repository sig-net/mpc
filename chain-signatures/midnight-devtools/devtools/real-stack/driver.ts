import { Transaction, hexlify, recoverAddress } from "ethers";
import { createInterface } from "node:readline";
import { join } from "node:path";
import { findDeployedContract, type FoundContract } from "@midnight-ntwrk/midnight-js/contracts";
import { setNetworkId } from "@midnight-ntwrk/midnight-js/network-id";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import {
  buildDeployTransaction,
  deploySignetContract,
  deploySignetResponder,
  deriveAccountKeys,
  GENESIS_MINT_WALLET_SEED,
  initialiseWalletFacade,
  isLocalStandaloneNetwork,
  registerNightForDustGeneration,
  submitUnprovenTransaction,
  waitForSpendableDust,
  withSyncedWalletFacade,
  type FacadeState,
  type MidnightNodeConfig,
  type WalletFacade,
} from "@sig-net/midnight-contract-deploy";
import {
  bytesToHex,
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
import { describeFailure } from "./errors.js";
import {
  fireTwin,
  prepareTwin,
  submitAdversarial,
  type AdversarialScenario,
} from "./adversarial.js";
import {
  submitPlacement,
  type IsEvenCall,
  type PlacementContext,
  type PlacementScenario,
} from "./fallible.js";
import { ledger, pureCircuits } from "./managed/caller/contract/index.js";
import type { CallPlacement } from "./placement.js";
import {
  buildCallerProviders,
  callerCompiledContract,
  CALLER_PRIVATE_STATE_ID,
  type CallerContract,
  type CallerProviders,
} from "./providers.js";
import { runVault, runVaultPartialSend } from "./vault.js";
import { createCallerPrivateState } from "./witnesses.js";

const DEPLOYER_SEED = "02".repeat(32);
const INVOKER_SEED = "03".repeat(32);
// The responder and the impersonating caller deploy from wallets of their own, so they
// run beside the deploys the deployer wallet pays for.
const RESPONDER_DEPLOYER_SEED = "f0".repeat(32);
const IMPERSONATOR_DEPLOYER_SEED = "f1".repeat(32);
// One funding wallet per MPC node: a publisher assumes it alone spends its wallet's DUST,
// and nodes sharing one wallet refuse each other's submissions as DUST double spends.
const publisherSeed = (node: number) => (4 + node).toString(16).padStart(2, "0").repeat(32);

type CallerHandle = FoundContract<CallerContract>;

interface BootstrapRequest {
  op: "bootstrap";
  config: MidnightNodeConfig;
  artifactDir: string;
  /** How many MPC nodes publish, each from its own funding wallet. */
  publishers: number;
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
  outputType?: "bool" | "uint256" | "bytes32";
  /** Raw output schema bytes as hex, in place of `outputType`. */
  outputSchema?: string;
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

interface PlacementCall {
  nonce: string;
  target: string;
  argument: string;
}

interface SubmitPlacementRequest {
  op: "submitPlacement";
  scenario: PlacementScenario;
  calls: PlacementCall[];
}

interface SubmitAdversarialRequest {
  op: "submitAdversarial";
  scenario: AdversarialScenario;
  call: PlacementCall;
}

interface PrepareTwinRequest {
  op: "prepareTwin";
  call: PlacementCall;
}

interface FireTwinRequest {
  op: "fireTwin";
  requestId: string;
  call: PlacementCall;
  failing: PlacementCall;
}

interface RunVaultRequest {
  op: "runVault";
  mpcPublicKey: string;
  evmRpcUrl: string;
  evmFunderKey: string;
}

interface RunVaultPartialSendRequest extends Omit<RunVaultRequest, "op"> {
  op: "runVaultPartialSend";
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
  | SubmitPlacementRequest
  | SubmitAdversarialRequest
  | PrepareTwinRequest
  | FireTwinRequest
  | RunVaultRequest
  | RunVaultPartialSendRequest
  | ShutdownRequest;

interface Session {
  config: MidnightNodeConfig;
  artifactDir: string;
  facade: WalletFacade;
  providers: CallerProviders;
  caller: CallerHandle;
  callerAddress: string;
  centralAddress: string;
  responderAddress: string;
  impersonator: CallerHandle;
  publicDataProvider: SignetPublicStateSource;
  reader: SignetRequestResponseReader;
  responseKey?: Secp256k1Point;
  /** Placement of the transaction most recently handed to the proof server. */
  lastPlacement?: CallPlacement[];
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

// The output schema must be canonical JSON NUL-padded to the caller's 64-byte field.
function padSchema(schema: Uint8Array): Uint8Array {
  if (schema.length > 64) throw new Error(`schema exceeds 64 bytes: ${schema.length}`);
  const padded = new Uint8Array(64);
  padded.set(schema);
  return padded;
}

function outputSchema(outputType: string): Uint8Array {
  return padSchema(
    new TextEncoder().encode(JSON.stringify([{ name: "success", type: outputType }])),
  );
}

function requestOutputSchema(request: SubmitRequest): Uint8Array {
  if (request.outputSchema !== undefined) {
    if (request.outputType !== undefined) throw new Error("give outputType or outputSchema");
    return padSchema(bytes(request.outputSchema));
  }
  if (request.outputType === undefined) throw new Error("outputType or outputSchema is required");
  return outputSchema(request.outputType);
}

async function waitFor<T>(description: string, read: () => Promise<T | undefined>): Promise<T> {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const value = await read();
    if (value !== undefined) return value;
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error(`timed out waiting for ${description}`);
}

// The SDK reports every failed submission with the same error, so name the bootstrap step.
async function step<T>(name: string, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    throw new Error(`${name} failed`, { cause: error });
  }
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

type UnshieldedAddress = FacadeState["unshielded"]["address"];

// The package's `transferNight` with one output per receiver, so one transaction funds
// every role instead of one finalized transfer each. Unlike it, this does not wait for
// DUST to generate: the caller retries a DUST shortfall.
async function transferNightToEach(
  facade: WalletFacade,
  keys: ReturnType<typeof deriveAccountKeys>,
  state: FacadeState,
  receivers: readonly UnshieldedAddress[],
  amount: bigint,
): Promise<void> {
  const nightTokenType = Object.keys(state.unshielded.balances)[0];
  if (nightTokenType === undefined) throw new Error("root holds no unshielded NIGHT to transfer");
  const ttl = new Date(Date.now() + 30 * 60 * 1000);
  const secretKeys = {
    shieldedSecretKeys: keys.shieldedSecretKeys,
    dustSecretKey: keys.dustSecretKey,
  };
  const transfer = await facade.transferTransaction(
    [
      {
        type: "unshielded",
        outputs: receivers.map((receiverAddress) => ({
          type: nightTokenType,
          receiverAddress,
          amount,
        })),
      },
    ],
    secretKeys,
    { ttl, payFees: false },
  );
  const recipe = await facade
    .balanceUnprovenTransaction(transfer.transaction, secretKeys, {
      ttl,
      tokenKindsToBalance: ["dust"],
    })
    .catch(async (error: unknown) => {
      await facade.revert(transfer).catch(() => undefined);
      throw error;
    });
  const signed = await facade.signRecipe(recipe, keys.unshieldedKeystore.signDataAsync);
  await facade.submitTransaction(await facade.finalizeRecipe(signed));
}

// Mirrors the package's per-child flow but amortizes the expensive parts: a root
// facade re-syncs from genesis once (that re-sync dominates wall time) and funds every
// role wallet in one transfer, and the independent child verifications run concurrently.
async function fundRoles(config: MidnightNodeConfig, publisherSeeds: string[]): Promise<void> {
  const networkId = config.networkId;
  const rootKeys = deriveAccountKeys(GENESIS_MINT_WALLET_SEED, networkId);
  const roles = [
    ["deployer", DEPLOYER_SEED],
    ["invoker", INVOKER_SEED],
    ["responder deployer", RESPONDER_DEPLOYER_SEED],
    ["impersonator deployer", IMPERSONATOR_DEPLOYER_SEED],
    ...publisherSeeds.map((seed, node) => [`publisher ${node}`, seed] as const),
  ] as const;
  const receivers = await step("syncing the role wallets' addresses", () =>
    Promise.all(
      roles.map(([, seed]) =>
        withSyncedWalletFacade(
          deriveAccountKeys(seed, networkId),
          config,
          async (_facade, state) => state.unshielded.address,
        ),
      ),
    ),
  );

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
    const amount = totalNight(state) / BigInt(roles.length + 2);
    if (amount === 0n) throw new Error("local genesis wallet cannot fund role wallets");
    await step("registering the root wallet's NIGHT for DUST", async () => {
      await registerNightForDustGeneration(rootFacade, rootKeys, state);
      if (state.dust.balance(new Date()) === 0n) await waitForSpendableDust(rootFacade, 1n);
    });

    const startedAt = Date.now();
    await step(
      `transferring NIGHT from the root wallet to ${roles.length} role wallets`,
      async () => {
        for (let attempt = 0; ; attempt += 1) {
          try {
            await transferNightToEach(rootFacade, rootKeys, state, receivers, amount);
            break;
          } catch (error) {
            if (attempt >= 11 || !isDustBalancingShortfall(error)) throw error;
            diagnostics(
              `root DUST is not yet enough to cover the role transfer; retrying (attempt ${attempt + 1})`,
            );
            await sleep(5_000);
            state = await rootFacade.waitForSyncedState();
          }
        }
      },
    );
    diagnostics(`funded ${roles.length} role wallets in ${Date.now() - startedAt}ms`);
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
        await step(`registering the ${name} wallet's NIGHT for DUST`, async () => {
          await registerNightForDustGeneration(facade, keys, state);
          if (state.dust.balance(new Date()) === 0n) await waitForSpendableDust(facade, 1n);
        });
      });
      diagnostics(`verified ${name} wallet in ${Date.now() - startedAt}ms`);
    }),
  );
}

async function bootstrap(request: BootstrapRequest) {
  if (session !== undefined) throw new Error("driver is already bootstrapped");
  setNetworkId(request.config.networkId);
  if (!Number.isInteger(request.publishers) || request.publishers < 1) {
    throw new Error(`expected a positive publisher count, got ${String(request.publishers)}`);
  }
  const publisherSeeds = Array.from({ length: request.publishers }, (_, node) =>
    publisherSeed(node),
  );
  diagnostics("funding real-stack role wallets");
  await fundRoles(request.config, publisherSeeds);
  // Each deploy pays from a freshly synced deployer facade, and a facade syncs from the
  // indexer, which indexes a block a moment after the node reports it final. A facade
  // synced in that gap still holds the DUST the previous deploy spent, and the node
  // refuses the new deploy's DUST spend (InvalidDustSpendProof), so wait for each deploy
  // to be indexed before the deployer wallet pays again.
  const publicData = indexerPublicDataProvider({
    queryURL: request.config.indexerUrl,
    subscriptionURL: request.config.indexerWsUrl,
  });
  // A failed query counts as not indexed yet, so a transient indexer error does not end the
  // bootstrap; a timeout names the last one.
  const indexed = async (contractAddress: string) => {
    let lastError: unknown;
    try {
      await waitFor(`the indexer to serve the contract deployed at ${contractAddress}`, () =>
        publicData.queryContractState(contractAddress).then(
          (state) => (state ? true : undefined),
          (error: unknown) => {
            lastError = error;
            return undefined;
          },
        ),
      );
    } catch (error) {
      if (lastError === undefined) throw error;
      const timeout = error instanceof Error ? error.message : String(error);
      throw new Error(`${timeout} (last query error: ${describeFailure(lastError)})`, {
        cause: error,
      });
    }
  };
  const deployerSecret = bytes(DEPLOYER_SEED, 32);
  const deployerCommitment = pureCircuits.deployerCommitment(deployerSecret);
  // The constructor stores only its arguments, so the wallet paying for a caller deploy
  // leaves no trace in the contract: the impersonator pays from its own wallet.
  const deployCaller = async (name: string, centralAddress: string, payerSeed: string) => {
    const payerKeys = deriveAccountKeys(payerSeed, request.config.networkId);
    const deployment = await step(`deploying the ${name}`, () =>
      withSyncedWalletFacade(payerKeys, request.config, async (facade) => {
        const built = await buildDeployTransaction(
          callerCompiledContract,
          request.config.networkId,
          payerKeys.shieldedSecretKeys.coinPublicKey,
          createCallerPrivateState(deployerSecret),
          deployerCommitment,
          contractAddressFromHex(centralAddress),
        );
        await submitUnprovenTransaction(facade, payerKeys, built.serializedTransaction);
        return { contractAddress: built.contractAddress };
      }),
    );
    await indexed(deployment.contractAddress);
    return deployment;
  };
  const deployCentralAndCallers = async () => {
    diagnostics("deploying central Signet contract");
    const central = await step("deploying the central Signet contract", () =>
      deploySignetContract(deployEnv(request.config, DEPLOYER_SEED)),
    );
    await indexed(central.contractAddress);
    diagnostics("deploying Compact caller and impersonating Compact caller");
    const [caller, impersonator] = await Promise.all([
      deployCaller("Compact caller", central.contractAddress, DEPLOYER_SEED),
      deployCaller(
        "impersonating Compact caller",
        central.contractAddress,
        IMPERSONATOR_DEPLOYER_SEED,
      ),
    ]);
    return { central, caller, impersonator };
  };
  const deployResponder = async () => {
    diagnostics("deploying Signet responder");
    const responder = await step("deploying the Signet responder", () =>
      deploySignetResponder(deployEnv(request.config, RESPONDER_DEPLOYER_SEED)),
    );
    await indexed(responder.contractAddress);
    return responder;
  };
  const [{ central, caller: callerDeployment, impersonator: impersonatorDeployment }, responder] =
    await Promise.all([deployCentralAndCallers(), deployResponder()]);
  const invokerKeys = deriveAccountKeys(INVOKER_SEED, request.config.networkId);
  const facade = await step("syncing the invoker wallet", async () => {
    const started = await initialiseWalletFacade(invokerKeys, request.config);
    await started.start(invokerKeys.shieldedSecretKeys, invokerKeys.dustSecretKey);
    await started.waitForSyncedState();
    return started;
  });
  const providers = buildCallerProviders(
    facade,
    invokerKeys,
    request.config,
    join(request.artifactDir, "caller.leveldb"),
    (placement) => {
      if (session !== undefined) session.lastPlacement = placement;
    },
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
    config: request.config,
    artifactDir: request.artifactDir,
    facade,
    providers,
    caller,
    callerAddress: callerDeployment.contractAddress,
    centralAddress: central.contractAddress,
    responderAddress: responder.contractAddress,
    impersonator,
    publicDataProvider: providers.publicDataProvider,
    reader: new SignetRequestResponseReader({
      requesterContractAddress: callerDeployment.contractAddress,
      requesterRequestsPath: [2],
      responderContractAddress: responder.contractAddress,
      publicDataProvider: providers.publicDataProvider,
      eventSource: signetEventSourceFromIndexer({ queryUrl: request.config.indexerUrl }),
    }),
  };
  return {
    centralAddress: central.contractAddress,
    responderAddress: responder.contractAddress,
    callerAddress: callerDeployment.contractAddress,
    publisherSeeds,
  };
}

function isEvenCall(call: PlacementCall): IsEvenCall {
  return {
    evmNonce: BigInt(call.nonce),
    to: bytes(call.target, 20),
    argWord: bytes(call.argument, 32),
  };
}

function placementContext(active: Session): PlacementContext {
  return {
    providers: active.providers,
    callerAddress: active.callerAddress,
    signetAddress: active.centralAddress,
    schema: outputSchema("bool"),
    bumpGate: () => active.caller.callTx.bumpGate(),
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
  if (request.op === "runVault" || request.op === "runVaultPartialSend") {
    return (request.op === "runVault" ? runVault : runVaultPartialSend)({
      config: active.config,
      artifactDir: active.artifactDir,
      centralAddress: active.centralAddress,
      responderAddress: active.responderAddress,
      mpcPublicKey: request.mpcPublicKey,
      evmRpcUrl: request.evmRpcUrl,
      evmFunderKey: request.evmFunderKey,
      deployerSeed: DEPLOYER_SEED,
      userSeed: INVOKER_SEED,
      userFacade: active.facade,
    });
  }
  if (request.op === "submitPlacement") {
    return submitPlacement(
      placementContext(active),
      request.scenario,
      request.calls.map(isEvenCall),
    );
  }
  if (request.op === "submitAdversarial") {
    return submitAdversarial(placementContext(active), request.scenario, isEvenCall(request.call));
  }
  if (request.op === "prepareTwin") {
    return prepareTwin(placementContext(active), isEvenCall(request.call));
  }
  if (request.op === "fireTwin") {
    return fireTwin(
      placementContext(active),
      request.requestId.replace(/^0x/i, "").toLowerCase(),
      isEvenCall(request.call),
      isEvenCall(request.failing),
    );
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
            : serializedOutput.length === 20
              ? pureCircuits.checkResponse20
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
    const flipFirst = (value: Uint8Array) =>
      value.map((byte, index) => (index === 0 ? byte ^ 1 : byte));
    for (const [field, value] of [
      ["requestId", { ...circuitInput, requestId: flipFirst(circuitInput.requestId) }],
      ["blockHeight", { ...circuitInput, blockHeight: circuitInput.blockHeight ^ 1n }],
      ["outputKind", { ...circuitInput, outputKind: (circuitInput.outputKind + 1) % 3 }],
      [
        "serializedOutputLength",
        { ...circuitInput, serializedOutputLength: circuitInput.serializedOutputLength ^ 1n },
      ],
      ["outputHash", { ...circuitInput, outputHash: flipFirst(circuitInput.outputHash) }],
    ] as const) {
      if (check(value, serializedOutput, responseKey))
        throw new Error(`accepted tampered ${field}`);
    }
    if (serializedOutput.length > 0) {
      if (check(circuitInput, flipFirst(serializedOutput), responseKey))
        throw new Error("accepted tampered serialized output");
    }
    const wrongWidth = new Uint8Array(serializedOutput.length === 32 ? 20 : 32);
    wrongWidth.set(serializedOutput.subarray(0, wrongWidth.length));
    const checkWrongWidth =
      wrongWidth.length === 20 ? pureCircuits.checkResponse20 : pureCircuits.checkResponse32;
    if (checkWrongWidth(circuitInput, wrongWidth, responseKey))
      throw new Error("accepted serialized output at a different width");
    // The upstream checker recomputes the digest from the other event fields; the
    // carried digest is reader metadata and deliberately excluded from verification.
    if (
      !check(
        { ...circuitInput, digest: flipFirst(circuitInput.digest) },
        serializedOutput,
        responseKey,
      )
    )
      throw new Error("reader metadata changed upstream circuit verification");
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
            : serializedOutput.length === 20
              ? active.caller.callTx.verifyResponse20
              : serializedOutput.length === 32
                ? active.caller.callTx.verifyResponse32
                : undefined;
    if (verify === undefined)
      throw new Error(`unsupported output width ${serializedOutput.length}`);
    await verify(circuitInput, serializedOutput);
    await waitFor("the caller request to be removed", async () =>
      (await callerHasRequest(active, requestId)) ? undefined : true,
    );
    let duplicateRejected = false;
    try {
      await verify(circuitInput, serializedOutput);
    } catch (error) {
      if (!String(error).includes("Request not found")) throw error;
      duplicateRejected = true;
    }
    if (!duplicateRejected) throw new Error("Compact accepted a duplicate settlement");
    if (await callerHasRequest(active, requestId))
      throw new Error("duplicate settlement restored the consumed request");
    return {};
  }
  const submitted = await active.caller.callTx.submitIsEvenRequest(
    BigInt(request.nonce),
    1n,
    bytes(request.target, 20),
    bytes(request.argument, 32),
    requestOutputSchema(request),
  );
  return { requestId: bytesToHex(submitted.private.result), placement: active.lastPlacement };
}

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  try {
    const result = await dispatch(JSON.parse(line) as Request);
    process.stdout.write(`${JSON.stringify({ ok: true, result })}\n`);
  } catch (error) {
    // The SDK's errors keep the node's own refusal (its `1010: Invalid Transaction` code, say)
    // in their cause chain, which the stack does not show.
    const described = describeFailure(error);
    const reply =
      error instanceof Error && error.stack ? `${described}\n${error.stack}` : described;
    diagnostics(`request failed: ${reply}`);
    process.stdout.write(`${JSON.stringify({ ok: false, error: reply })}\n`);
  }
}
await session?.facade.stop().catch(() => undefined);
