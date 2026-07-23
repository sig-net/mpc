/**
 * `POST /respond`: validate, prove, pay, submit.
 *
 * MECHANISM, NEVER AUTHORITY. The signature was computed by the MPC threshold
 * before anything reached this service, and both circuits are blind appends. The
 * validation below is a shape check that keeps malformed input away from the
 * prover, not an authorization check.
 *
 * The escape hatch rather than `findDeployedContract`: three pinned reads, then
 * `createUnprovenCallTxFromInitialStates` with `crossContract` omitted, then the
 * stock proof provider, then balance and submit. That is the only entry point
 * needing no `PublicDataProvider`, no indexer read and no private-state provider.
 *
 * The wire contract is byte-identical to the Rust implementation it replaces.
 */

import { ContractExecutable } from "@midnight-ntwrk/midnight-js-protocol/compact-js";
import type { ContractState } from "@midnight-ntwrk/midnight-js-protocol/compact-runtime";
import type { UnboundTransaction, VerifierKey } from "@midnight-ntwrk/midnight-js-types";
import { httpClientProofProvider } from "@midnight-ntwrk/midnight-js-http-client-proof-provider";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import {
  isDeserializationError,
  deserializeCompactContractState,
  deserializeLedgerParameters,
  deserializeZswapChainState,
} from "@midnight-ntwrk/midnight-js-utils";
import {
  ContractTypeError,
  createCallTxOptions,
  createUnprovenCallTxFromInitialStates,
  verifyContractState,
  type PublicContractStates,
} from "@midnight-ntwrk/midnight-js/contracts";
import { setNetworkId } from "@midnight-ntwrk/midnight-js/network-id";
import {
  Contract as SignetContract,
  createSignetContractPrivateState,
  type SignetContractCircuitId,
  type SignetContractPrivateState,
} from "@sig-net/midnight-contract";
import { makeVacantCompiledContract } from "@sig-net/midnight-contract-deploy";

import { redact, type Config } from "./config.js";
import {
  badRequest,
  classify,
  jsonObject,
  PublisherError,
  RESPOND_STAGES,
  fail,
  type Reply,
  type RespondStage,
} from "./errors.js";
import { assertLedgerTag, LEDGER_TAGS } from "./ledger.js";
import { finalizedHead, fromHex, isHex, runtimeApiBytes, type BlockHashHex, type NodeClient } from "./node.js";
import { openFundingWallet } from "./wallet.js";

// ---- the wire contract -----------------------------------------------------

/**
 * `sig_r`/`sig_s` are LITTLE-ENDIAN, the order the record's `Bytes<32>` fields
 * store. `serialized_output` is the whole zero-padded ABI return data, not a
 * digest. The contract checks none of it: consumers verify on claim.
 */
export interface RespondRequest {
  readonly contract_address: string;
  readonly circuit: string;
  readonly request_id: string;
  /** `postSignatureResponse` -> `SignatureRespondedEvent { bigRx, bigRy, s, recoveryId }`. */
  readonly big_r_x?: string;
  readonly big_r_y?: string;
  readonly s?: string;
  /** `postRespondBidirectional` -> `RespondBidirectionalEvent { serializedOutput, outputLen, r, s, recoveryId }`. */
  readonly serialized_output?: string;
  readonly output_len?: number;
  readonly sig_r?: string;
  readonly sig_s?: string;
  /** Parity of R.y, carried by BOTH events for off-chain key recovery. */
  readonly recovery_id?: number;
}

export type ValidatedRespondRequest =
  | (RespondRequest & {
      readonly circuit: "postSignatureResponse";
      readonly big_r_x: string;
      readonly big_r_y: string;
      readonly s: string;
      readonly recovery_id: number;
    })
  | (RespondRequest & {
      readonly circuit: "postRespondBidirectional";
      readonly serialized_output: string;
      readonly output_len: number;
      readonly sig_r: string;
      readonly sig_s: string;
      readonly recovery_id: number;
    });

/** Derived from the validated union so the two cannot drift. */
export type RespondCircuit = ValidatedRespondRequest["circuit"];

// ---- parsing and validation ------------------------------------------------

/** Rust's serde treats `null` and a missing key alike. */
const absent = (value: unknown): boolean => value === undefined || value === null;

function requiredString(source: Record<string, unknown>, field: string): string {
  const value = optionalString(source, field);
  if (value !== undefined) return value;
  throw badRequest(`invalid JSON: missing field \`${field}\``);
}

function optionalString(source: Record<string, unknown>, field: string): string | undefined {
  const value = source[field];
  if (absent(value)) return undefined;
  if (typeof value === "string") return value;
  throw badRequest(`invalid JSON: \`${field}\` must be a string`);
}

function optionalByte(source: Record<string, unknown>, field: string): number | undefined {
  const value = source[field];
  if (absent(value)) return undefined;
  if (typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 255) return value;
  throw badRequest(`invalid JSON: \`${field}\` must be an integer in 0..=255`);
}

/** Unknown fields are ignored, as the Rust struct does. */
export function parseRespondRequest(body: string): RespondRequest {
  const source = jsonObject(body);

  return {
    contract_address: requiredString(source, "contract_address"),
    circuit: requiredString(source, "circuit"),
    request_id: requiredString(source, "request_id"),
    big_r_x: optionalString(source, "big_r_x"),
    big_r_y: optionalString(source, "big_r_y"),
    s: optionalString(source, "s"),
    serialized_output: optionalString(source, "serialized_output"),
    output_len: optionalByte(source, "output_len"),
    sig_r: optionalString(source, "sig_r"),
    sig_s: optionalString(source, "sig_s"),
    recovery_id: optionalByte(source, "recovery_id"),
  };
}

/** Present and exactly 32 bytes of lowercase hex. */
const isHex32 = (value: string | undefined): boolean => value !== undefined && isHex(value, 32);

/** Checks and their order are byte-identical to the Rust `validate`. */
export function validateRespondRequest(request: RespondRequest): asserts request is ValidatedRespondRequest {
  if (!isHex(request.contract_address, 32)) throw badRequest("contract_address must be 64 lowercase hex");
  if (!isHex(request.request_id, 32)) throw badRequest("request_id must be 64 hex");

  switch (request.circuit) {
    case "postSignatureResponse":
      if (!(isHex32(request.big_r_x) && isHex32(request.big_r_y) && isHex32(request.s))) {
        throw badRequest("postSignatureResponse needs big_r_x/big_r_y/s as 64 lowercase hex each");
      }
      if (!(request.recovery_id !== undefined && request.recovery_id <= 1)) {
        throw badRequest("postSignatureResponse recovery_id must be 0|1");
      }
      if ([request.serialized_output, request.output_len, request.sig_r, request.sig_s].some((f) => f !== undefined)) {
        throw badRequest("postSignatureResponse takes no bidirectional fields");
      }
      return;
    case "postRespondBidirectional":
      // serialized_output is Bytes<128>: the whole zero-padded ABI return data,
      // not a digest of it.
      if (!(request.serialized_output !== undefined && isHex(request.serialized_output, 128))) {
        throw badRequest("postRespondBidirectional needs serialized_output as 256 lowercase hex (Bytes<128>)");
      }
      if (!(request.output_len !== undefined && request.output_len <= 128)) {
        throw badRequest("postRespondBidirectional output_len must be 0..=128");
      }
      if (!(isHex32(request.sig_r) && isHex32(request.sig_s))) {
        throw badRequest("postRespondBidirectional needs sig_r/sig_s as 64 lowercase hex each");
      }
      if (!(request.recovery_id !== undefined && request.recovery_id <= 1)) {
        throw badRequest("postRespondBidirectional recovery_id must be 0|1");
      }
      if (request.big_r_x !== undefined || request.big_r_y !== undefined || request.s !== undefined) {
        throw badRequest("postRespondBidirectional takes no postSignatureResponse fields");
      }
      return;
    default:
      throw badRequest(`unknown circuit ${request.circuit}`);
  }
}

// ---- circuit arguments -----------------------------------------------------

/** Each circuit's arguments, read off the generated contract so a rename or retype upstream is a compile error here. */
type CircuitArgs<K extends RespondCircuit> = readonly [
  requestId: Uint8Array,
  event: Readonly<Parameters<SignetContract<SignetContractPrivateState>["circuits"][K]>[2]>,
];

export type SignatureRespondedEvent = CircuitArgs<"postSignatureResponse">[1];
export type RespondBidirectionalEvent = CircuitArgs<"postRespondBidirectional">[1];

export type RespondCall = {
  [K in RespondCircuit]: { readonly circuitId: K; readonly args: CircuitArgs<K> };
}[RespondCircuit];

/** `sig_r`/`sig_s` pass through unreversed: already the order the circuit's cast expects. */
export function respondCall(request: ValidatedRespondRequest): RespondCall {
  const requestId = fromHex(request.request_id);
  if (request.circuit === "postSignatureResponse") {
    return {
      circuitId: "postSignatureResponse",
      args: [
        requestId,
        {
          bigRx: fromHex(request.big_r_x),
          bigRy: fromHex(request.big_r_y),
          s: fromHex(request.s),
          recoveryId: BigInt(request.recovery_id),
        },
      ],
    };
  }
  return {
    circuitId: "postRespondBidirectional",
    args: [
      requestId,
      {
        serializedOutput: fromHex(request.serialized_output),
        outputLen: BigInt(request.output_len),
        r: fromHex(request.sig_r),
        s: fromHex(request.sig_s),
        recoveryId: BigInt(request.recovery_id),
      },
    ],
  };
}

// ---- the pinned reads ------------------------------------------------------

/**
 * The three states a call is built from, all read at one pinned finalized block.
 *
 * The library's own triple, so the dual-WASM split (`contractState` is
 * compact-runtime's, the other two ledger-v9's) is pinned by the package that
 * defines it rather than by a comment here.
 */
type CallStates = PublicContractStates & { readonly blockHash: BlockHashHex };

/**
 * The one place this service reads the chain. The reads must be fresh at prove
 * time — stale ledger parameters are rejected as `OutOfGas` because fees drift
 * per block — and the node connection exists for the wallet anyway.
 */
async function readCallStates(client: NodeClient, address: string): Promise<CallStates> {
  const blockHash = await finalizedHead(client);
  const [rawContract, rawZswap, rawParams] = await Promise.all([
    runtimeApiBytes(client, blockHash, "getContractState", `0x${address}`),
    runtimeApiBytes(client, blockHash, "getZswapChainState", `0x${address}`),
    runtimeApiBytes(client, blockHash, "getLedgerParameters"),
  ]);

  if (rawContract === undefined) {
    throw new PublisherError("contract_absent", `no contract state at ${address} in block ${blockHash} (is it deployed?)`);
  }
  if (rawZswap === undefined) {
    throw new PublisherError("contract_absent", `no zswap chain state for ${address} in block ${blockHash}`);
  }
  if (rawParams === undefined) {
    throw new Error(`node returned no ledger parameters at block ${blockHash}`);
  }

  assertLedgerTag(rawContract, LEDGER_TAGS.contractState, "contract state");
  assertLedgerTag(rawZswap, LEDGER_TAGS.zswapChainState, "zswap chain state");
  assertLedgerTag(rawParams, LEDGER_TAGS.ledgerParameters, "ledger parameters");

  const ctx = { caller: "midnight-publisher:readCallStates" };
  return {
    blockHash,
    // Not interchangeable: `deserializeCompactContractState` is
    // onchain-runtime-v4's, the other two are ledger-v9's.
    contractState: deserializeCompactContractState(rawContract, ctx),
    zswapChainState: deserializeZswapChainState(rawZswap, ctx),
    ledgerParameters: deserializeLedgerParameters(rawParams, ctx),
  };
}

// ---- the publisher: wallet, keys, proof server -----------------------------

/** Whatever {@link buildPublisher} assembles; stated once, there. */
type Publisher = Readonly<Awaited<ReturnType<typeof buildPublisher>>>;

let publisherPromise: Promise<Publisher> | undefined;

async function buildPublisher(config: Config) {
  // Global, and required before any transaction is built: it decides the
  // network id baked into the transaction and into address encoding.
  setNetworkId(config.networkId);

  const zkConfigProvider = new NodeZkConfigProvider<SignetContractCircuitId>(config.managedDir);
  // `managedDir` stays the caller's, deliberately: the package's neighbouring
  // `signetContractCompiledContract` resolves assets from the installed
  // contract package instead, which would defeat `MIDNIGHT_PUB_MANAGED_DIR` and
  // gut `assertCompiledContractMatches`'s error, whose whole point is to say
  // "point MIDNIGHT_PUB_MANAGED_DIR at the assets this contract was deployed
  // from".
  const compiledContract = makeVacantCompiledContract<SignetContract<SignetContractPrivateState>, SignetContractPrivateState>(
    "signet-contract",
    SignetContract,
    config.managedDir,
  );
  const verifierKeys: readonly [SignetContractCircuitId, VerifierKey][] = await zkConfigProvider.getVerifierKeys(
    ContractExecutable.make(compiledContract).getProvableCircuitIds(),
  );

  return {
    wallet: await openFundingWallet(config),
    zkConfigProvider,
    proofProvider: httpClientProofProvider(config.proofServerUrl, zkConfigProvider),
    compiledContract,
    verifierKeys,
  };
}

/** Lazy: a failed attempt clears the memo so the next request retries. */
function publisher(config: Config): Promise<Publisher> {
  if (publisherPromise === undefined) {
    publisherPromise = buildPublisher(config).catch((error: unknown) => {
      publisherPromise = undefined;
      throw error;
    });
  }
  return publisherPromise;
}

/** For tests and one-shot scripts. */
export async function closePublisher(): Promise<void> {
  const pending = publisherPromise;
  publisherPromise = undefined;
  if (pending === undefined) return;
  await pending.then((ready) => ready.wallet.close()).catch(() => undefined);
}

/** The `verifyContractState` check the escape-hatch route skips, against the state already read. */
function assertCompiledContractMatches(
  ready: Publisher,
  state: ContractState,
  address: string,
  managedDir: string,
): void {
  try {
    verifyContractState([...ready.verifierKeys], state);
  } catch (error) {
    if (error instanceof ContractTypeError) {
      throw new PublisherError(
        "contract_mismatch",
        `compiled contract in ${managedDir} does not match the contract deployed at ${address}: ` +
          `verifier keys differ or are absent for [${error.circuitIds.join(", ")}]. ` +
          `A proof built here would be rejected by the chain. Rebuild the contract assets, or point ` +
          `MIDNIGHT_PUB_MANAGED_DIR at the assets this contract was deployed from.`,
      );
    }
    throw error;
  }
}

// ---- the flow --------------------------------------------------------------

async function proveCall(ready: Publisher, call: RespondCall, address: string, states: CallStates): Promise<UnboundTransaction> {
  const dependencies = {
    coinPublicKey: ready.wallet.getCoinPublicKey(),
    initialContractState: states.contractState,
    initialZswapChainState: states.zswapChainState,
    ledgerParameters: states.ledgerParameters,
    // Inline, which is why no private-state provider is needed. The contract
    // declares no witnesses, so it is never consulted.
    initialPrivateState: createSignetContractPrivateState(),
  };

  // Collapsing the ternary does not compile: `createCallTxOptions` types `args`
  // against the circuit id, so each arm needs a literal one.
  const options =
    call.circuitId === "postSignatureResponse"
      ? createCallTxOptions(ready.compiledContract, call.circuitId, address, undefined, undefined, [call.args[0], call.args[1]])
      : createCallTxOptions(ready.compiledContract, call.circuitId, address, undefined, undefined, [call.args[0], call.args[1]]);

  const unsubmitted = await createUnprovenCallTxFromInitialStates(
    ready.zkConfigProvider,
    { ...options, ...dependencies },
    ready.wallet.getEncryptionPublicKey(),
  );

  return ready.proofProvider.proveTx(unsubmitted.private.unprovenTx);
}

/** A {@link PublisherError} passes through; anything else is named by its stage. */
async function inStage<T>(stage: RespondStage, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof PublisherError) throw error;
    // A deserialization failure is NOT an unreachable node, which is what the
    // read stage's fallback would otherwise call it — telling the caller to
    // retry a condition no amount of retrying resolves.
    if (isDeserializationError(error) && error.context.extracted?.receivedVersion !== undefined) {
      throw new PublisherError("ledger_mismatch", describeFailure(error));
    }
    const described = describeFailure(error);
    // Classified against a WIDER haystack than the message it answers with.
    // Effect's `FiberFailure` keeps its cause on a Symbol, not on `.cause`, so
    // `describeFailure`'s walk cannot reach it and every submit failure renders
    // as the same constant `SubmissionError: Transaction submission error`.
    // `String(error)` runs Effect's own `Cause.pretty` and does render the
    // nested chain. It is multi-line with stack frames, so it is fit for
    // matching and not for a response body.
    throw new PublisherError(classify(stage, `${described}\n${String(error)}`), described);
  }
}

/** The whole post: pinned reads, key check, prove, balance, submit. */
async function post(
  config: Config,
  client: NodeClient,
  ready: Publisher,
  request: ValidatedRespondRequest,
): Promise<string> {
  const states = await inStage(RESPOND_STAGES.read, () => readCallStates(client, request.contract_address));
  assertCompiledContractMatches(ready, states.contractState, request.contract_address, config.managedDir);
  const call = respondCall(request);
  const proven = await inStage(RESPOND_STAGES.prove, () => proveCall(ready, call, request.contract_address, states));
  const balanced = await inStage(RESPOND_STAGES.balance, () => ready.wallet.balanceTx(proven));
  return inStage(RESPOND_STAGES.submit, () => ready.wallet.submitTx(balanced));
}

function describeOne(value: unknown): string {
  if (value instanceof Error) {
    return [value.name === "Error" ? "" : value.name, value.message].filter(Boolean).join(": ");
  }
  if (typeof value !== "object" || value === null) return String(value);
  const { _tag, message } = value as { _tag?: unknown; message?: unknown };
  const named = [_tag, message].filter((part) => typeof part === "string" && part.length > 0).join(": ");
  if (named.length > 0) return named;
  try {
    // Anything else: better an object literal than `[object Object]`.
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

/**
 * One line that NAMES the failure, causes innermost last. `message` alone is not
 * enough: Effect's `FiberFailure` keeps the failing class in `name`, and
 * `classify` matches against this output.
 */
export function describeFailure(error: unknown): string {
  const parts: string[] = [];
  // Bounded, so a self-referential `cause` chain terminates rather than hangs.
  for (let current: unknown = error, depth = 0; current !== undefined && current !== null && depth < 8; depth += 1) {
    const text = describeOne(current);
    // A wrapper usually quotes what it wrapped; do not say it twice.
    if (text.length > 0 && !parts.some((part) => part.includes(text))) parts.push(text);
    current = typeof current === "object" ? (current as { cause?: unknown }).cause : undefined;
  }
  return parts.join(": ") || String(error);
}

/**
 * A 200 means finalized, equivalent to `SucceedEntirely` here: both circuits run
 * wholly in the guaranteed phase, so inclusion is success.
 *
 * NOT SERIALIZED AND NOT RETRIED, so the caller owns two collisions: concurrent
 * posts share one dust UTXO and collide at balance time (`wallet_unfunded`,
 * ~35s), and two posts under one request id lose the ledger's optimistic-
 * concurrency check (`state_conflict`, never charged). Anyone adding a queue
 * must keep the state reads inside it, or the parameters go stale.
 */
export async function handleRespond(config: Config, client: NodeClient, body: string): Promise<Reply> {
  try {
    const validated = parseRespondRequest(body);
    validateRespondRequest(validated);
    console.log(`respond: circuit=${validated.circuit} rid=${validated.request_id}`);
    // Deliberately not staged: a failure here is this service failing to start
    // (unreadable `managedDir`, unreachable indexer, bad seed), which no stage
    // code describes better than `internal` plus the message itself.
    const ready = await publisher(config);
    const txId = await post(config, client, ready, validated);
    console.log(`respond: rid=${validated.request_id} submitted tx ${txId}`);
    return { status: 200, body: `{"status":"ok"}` };
  } catch (error) {
    // Redacted at the source: wallet, proof-server and node errors can echo
    // values they were handed, and this text becomes both a response body and a
    // log line. The funding seed must never survive the trip.
    const failure = error instanceof PublisherError ? error : new PublisherError("internal", describeFailure(error));
    const safe = redact(failure.message, [config.fundingSeed]);
    // A 400 is the caller's own request coming back at it and is not worth a log
    // line; everything else is this service failing to do its job.
    if (failure.code !== "bad_request") console.error(`respond failed [${failure.code}]: ${safe}`);
    return fail(failure.code, safe);
  }
}
