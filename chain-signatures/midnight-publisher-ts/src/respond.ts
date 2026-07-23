/**
 * `POST /respond`: the write seam. Validate, prove, pay, submit.
 *
 * MECHANISM, NEVER AUTHORITY. The signature was computed by the MPC threshold
 * before anything reached this service, and both circuits are blind appends
 * (counter increment plus map insert, no assert). The validation below is a
 * shape check that keeps malformed input away from the prover, not an
 * authorization check.
 *
 * The escape hatch rather than `findDeployedContract`: three pinned reads, then
 * `createUnprovenCallTxFromInitialStates` with `crossContract` omitted, then the
 * stock proof provider, then balance and submit. That needs no
 * `PublicDataProvider`, no indexer on the read side and no private-state
 * provider, so no directory is created and no database handle is taken. What it
 * gives up is `verifyContractState`, reproduced below against the same contract
 * state the call is built from.
 *
 * The wire contract (field names, optionality, lengths, the lowercase-hex rule,
 * cross-circuit exclusion, every message and the order the checks run in) is
 * byte-identical to the Rust implementation this replaces, EXCEPT that the Rust
 * one still validates `postRespond`, a circuit that no longer exists on chain.
 */

import { ContractExecutable, type CompiledContract } from "@midnight-ntwrk/midnight-js-protocol/compact-js";
import type { ContractState } from "@midnight-ntwrk/midnight-js-protocol/compact-runtime";
import type { LedgerParameters, ZswapChainState } from "@midnight-ntwrk/midnight-js-protocol/ledger";
import type { UnboundTransaction, VerifierKey } from "@midnight-ntwrk/midnight-js-types";
import { httpClientProofProvider } from "@midnight-ntwrk/midnight-js-http-client-proof-provider";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import {
  deserializeCompactContractState,
  deserializeLedgerParameters,
  deserializeZswapChainState,
} from "@midnight-ntwrk/midnight-js-utils";
import {
  ContractTypeError,
  createCallTxOptions,
  createUnprovenCallTxFromInitialStates,
  verifyContractState,
} from "@midnight-ntwrk/midnight-js/contracts";
import { setNetworkId } from "@midnight-ntwrk/midnight-js/network-id";
import type { ProofProvider } from "@midnight-ntwrk/midnight-js/types";
import {
  Contract,
  createSignetContractPrivateState,
  type SignetContractCircuitId,
  type SignetContractPrivateState,
} from "@sig-net/midnight-contract";
import { makeVacantCompiledContract } from "@sig-net/midnight-contract-deploy";

import { redact, secrets, type Config } from "./config.js";
import {
  badRequest,
  classify,
  errorBody,
  PublisherError,
  RESPOND_STAGES,
  statusFor,
  type RespondStage,
} from "./errors.js";
import { assertLedgerTag, LEDGER_TAGS } from "./ledger.js";
import { finalizedHead, fromHex, isHex, runtimeApiBytes, type BlockHashHex, type NodeClient } from "./node.js";
import { openFundingWallet, type FundingWallet } from "./wallet.js";
import type { Reply } from "./server.js";

// ---- the wire contract -----------------------------------------------------

/**
 * Mirrors the Rust `RespondRequest` field for field; the two cannot share a
 * type, so the JSON contract is pinned by identical fixtures on both sides.
 *
 * `sig_r`/`sig_s` are LITTLE-ENDIAN, the order the record's `Bytes<32>` fields
 * store; the caller byte-reverses k256's big-endian scalars before posting.
 * `serialized_output` is the WHOLE zero-padded ABI return data, not a digest.
 * The contract checks none of it: consumers verify on claim.
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

/** Making the guarantee a type is what keeps {@link respondCall} free of non-null assertions. */
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

/**
 * One of the two circuits this seam posts to.
 *
 * Derived from the validated union rather than declared beside it, so the two
 * cannot drift. A rename upstream is already a compile error at `proveCall`,
 * where `createCallTxOptions` types its arguments against the generated
 * contract.
 */
export type RespondCircuit = ValidatedRespondRequest["circuit"];

// ---- parsing and validation ------------------------------------------------

/** Whether a JSON value is absent for an optional field. Rust's serde treats `null` and a missing key alike. */
function absent(value: unknown): boolean {
  return value === undefined || value === null;
}

function requiredString(source: Record<string, unknown>, field: string): string {
  const value = source[field];
  if (typeof value === "string") return value;
  throw badRequest(
    absent(value) ? `invalid JSON: missing field \`${field}\`` : `invalid JSON: \`${field}\` must be a string`,
  );
}

function optionalString(source: Record<string, unknown>, field: string): string | undefined {
  const value = source[field];
  if (absent(value)) return undefined;
  if (typeof value === "string") return value;
  throw badRequest(`invalid JSON: \`${field}\` must be a string`);
}

/** An optional `u8`, matching the Rust field type: an integer in 0..=255 or absent. */
function optionalByte(source: Record<string, unknown>, field: string): number | undefined {
  const value = source[field];
  if (absent(value)) return undefined;
  if (typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 255) return value;
  throw badRequest(`invalid JSON: \`${field}\` must be an integer in 0..=255`);
}

/** Unknown fields are ignored, matching the Rust struct's lack of `deny_unknown_fields`. */
export function parseRespondRequest(body: string): RespondRequest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (error) {
    throw badRequest(`invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw badRequest("invalid JSON: expected a JSON object");
  }
  const source = parsed as Record<string, unknown>;

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
function isHex32(value: string | undefined): boolean {
  return value !== undefined && isHex(value, 32);
}

/** Checks and order are byte-identical to the Rust `validate`, so the same body yields the same message. */
export function validateRespondRequest(request: RespondRequest): asserts request is ValidatedRespondRequest {
  if (!isHex(request.contract_address, 32)) {
    throw badRequest("contract_address must be 64 lowercase hex");
  }
  if (!isHex(request.request_id, 32)) {
    throw badRequest("request_id must be 64 hex");
  }

  switch (request.circuit) {
    case "postSignatureResponse": {
      if (!(isHex32(request.big_r_x) && isHex32(request.big_r_y) && isHex32(request.s))) {
        throw badRequest("postSignatureResponse needs big_r_x/big_r_y/s as 64 lowercase hex each");
      }
      if (!(request.recovery_id !== undefined && request.recovery_id <= 1)) {
        throw badRequest("postSignatureResponse recovery_id must be 0|1");
      }
      if (
        request.serialized_output !== undefined ||
        request.output_len !== undefined ||
        request.sig_r !== undefined ||
        request.sig_s !== undefined
      ) {
        throw badRequest("postSignatureResponse takes no bidirectional fields");
      }
      return;
    }
    case "postRespondBidirectional": {
      // serialized_output is Bytes<128>: the whole zero-padded ABI return data,
      // not a digest of it.
      if (!(request.serialized_output !== undefined && isHex(request.serialized_output, 128))) {
        throw badRequest(
          "postRespondBidirectional needs serialized_output as 256 lowercase hex (Bytes<128>)",
        );
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
    }
    default:
      throw badRequest(`unknown circuit ${request.circuit}`);
  }
}

/** One step, so the assertion's narrowing survives into the caller. */
export function parseAndValidate(body: string): ValidatedRespondRequest {
  const request = parseRespondRequest(body);
  validateRespondRequest(request);
  return request;
}

// ---- circuit arguments -----------------------------------------------------

/** `postSignatureResponse`'s second argument: the whole `SignatureRespondedEvent`. */
export interface SignatureRespondedEvent {
  readonly bigRx: Uint8Array;
  readonly bigRy: Uint8Array;
  readonly s: Uint8Array;
  readonly recoveryId: bigint;
}

/** `postRespondBidirectional`'s second argument: the whole `RespondBidirectionalEvent`. */
export interface RespondBidirectionalEvent {
  readonly serializedOutput: Uint8Array;
  readonly outputLen: bigint;
  readonly r: Uint8Array;
  readonly s: Uint8Array;
  readonly recoveryId: bigint;
}

/**
 * Both circuits take the request id then the whole event struct, because that is
 * what the Compact contract declares. The generated types make a wrong shape a
 * compile error; the retired toolkit's JSON5 argv codec made it a runtime one.
 */
export type RespondCall =
  | { readonly circuitId: "postSignatureResponse"; readonly args: readonly [Uint8Array, SignatureRespondedEvent] }
  | { readonly circuitId: "postRespondBidirectional"; readonly args: readonly [Uint8Array, RespondBidirectionalEvent] };

/**
 * `sig_r`/`sig_s` pass through unreversed: they are already the little-endian
 * order the hub circuit's `Bytes<32> as Secp256k1Scalar` cast expects.
 */
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

/** The three states a call is built from, all read at one pinned finalized block. */
interface CallStates {
  readonly blockHash: BlockHashHex;
  readonly contractState: ContractState;
  readonly zswapChainState: ZswapChainState;
  readonly ledgerParameters: LedgerParameters;
}

/**
 * THE ONE PLACE THIS SERVICE READS THE CHAIN, and it stays here rather than
 * moving to the caller with the rest of the RPC. The reads must be FRESH AT
 * PROVE TIME: reusing parameters read a few blocks ago gets the transaction
 * rejected with `Transcript(Execution(OutOfGas))`, because fees drift per block.
 * Having the caller fetch them would put its queueing delay in between, and dust
 * recovery already rate-limits this service to about one post per 35 seconds.
 * The node connection has to exist anyway for the wallet, so three blobs over it
 * cost nothing and remove a staleness class.
 */
async function readCallStates(client: NodeClient, address: string): Promise<CallStates> {
  const blockHash = await finalizedHead(client);
  const [rawContract, rawZswap, rawParams] = await Promise.all([
    runtimeApiBytes(client, blockHash, "getContractState", `0x${address}`),
    runtimeApiBytes(client, blockHash, "getZswapChainState", `0x${address}`),
    runtimeApiBytes(client, blockHash, "getLedgerParameters"),
  ]);

  if (rawContract === undefined) {
    throw new PublisherError(
      "contract_absent",
      `no contract state at ${address} in block ${blockHash} (is the contract deployed?)`,
    );
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
    // NOT interchangeable, though the tuple looks homogeneous.
    // `deserializeCompactContractState` yields onchain-runtime-v4's
    // `ContractState`; the ledger-named `deserializeContractState` beside it
    // yields ledger-v9's, the wrong class here, and produces the classic
    // "expected instance of" dual-WASM failure. The other two ARE ledger-v9's.
    contractState: deserializeCompactContractState(rawContract, ctx),
    zswapChainState: deserializeZswapChainState(rawZswap, ctx),
    ledgerParameters: deserializeLedgerParameters(rawParams, ctx),
  };
}

// ---- the publisher: wallet, keys, proof server -----------------------------

/** Everything a write needs that outlives a single request. */
interface Publisher {
  readonly wallet: FundingWallet;
  readonly zkConfigProvider: NodeZkConfigProvider<SignetContractCircuitId>;
  readonly proofProvider: ProofProvider;
  readonly compiledContract: CompiledContract.CompiledContract<
    Contract<SignetContractPrivateState>,
    SignetContractPrivateState
  >;
  /** Local verifier keys, read once from `managedDir`; compared against every contract state. */
  readonly verifierKeys: readonly [SignetContractCircuitId, VerifierKey][];
}

let publisherPromise: Promise<Publisher> | undefined;

async function buildPublisher(config: Config): Promise<Publisher> {
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
  const compiledContract = makeVacantCompiledContract<Contract<SignetContractPrivateState>, SignetContractPrivateState>(
    "signet-contract",
    Contract,
    config.managedDir,
  );
  const verifierKeys = await zkConfigProvider.getVerifierKeys(
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

/**
 * Lazy so the read seams stay available when the indexer or proof server is
 * down, and so a transient failure does not permanently poison the process: a
 * failed attempt clears the memo and the next request retries.
 */
function publisher(config: Config): Promise<Publisher> {
  if (publisherPromise === undefined) {
    publisherPromise = buildPublisher(config).catch((error: unknown) => {
      publisherPromise = undefined;
      throw error;
    });
  }
  return publisherPromise;
}

/** For tests and one-shot scripts; the service holds it for the process's lifetime. */
export async function closePublisher(): Promise<void> {
  const pending = publisherPromise;
  publisherPromise = undefined;
  if (pending === undefined) return;
  await pending.then((ready) => ready.wallet.close()).catch(() => undefined);
}

/**
 * The `verifyContractState` check the escape-hatch route skips. Without it a
 * stale `MIDNIGHT_PUB_MANAGED_DIR` surfaces only when the chain rejects the
 * finished proof, costing a prove and a balancing round. Run against the state
 * the call is built from, so no extra read, and every time, so a redeploy under
 * a running service is caught at once.
 */
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

/** Returns the proven, still unbalanced transaction. */
async function proveCall(ready: Publisher, call: RespondCall, address: string, states: CallStates): Promise<UnboundTransaction> {
  const dependencies = {
    coinPublicKey: ready.wallet.coinPublicKey,
    initialContractState: states.contractState,
    initialZswapChainState: states.zswapChainState,
    ledgerParameters: states.ledgerParameters,
    // Inline, which is why this route needs no private-state provider: nothing
    // is stored or read, no directory created. The contract declares no
    // witnesses, so this empty record is never consulted.
    initialPrivateState: createSignetContractPrivateState(),
  };

  // The ternary is NOT cosmetic and collapsing it does not compile:
  // `createCallTxOptions` types `args` against the circuit id, so each arm must
  // pass a literal one. `crossContract` is omitted, which is what lets the whole
  // route run without a `PublicDataProvider`.
  const options =
    call.circuitId === "postSignatureResponse"
      ? createCallTxOptions(ready.compiledContract, call.circuitId, address, undefined, undefined, [
          call.args[0],
          call.args[1],
        ])
      : createCallTxOptions(ready.compiledContract, call.circuitId, address, undefined, undefined, [
          call.args[0],
          call.args[1],
        ]);

  const unsubmitted = await createUnprovenCallTxFromInitialStates(
    ready.zkConfigProvider,
    { ...options, ...dependencies },
    ready.wallet.encryptionPublicKey,
  );

  return ready.proofProvider.proveTx(unsubmitted.private.unprovenTx);
}

/**
 * A {@link PublisherError} passes through: the throw site knew the cause and it
 * beats the stage. Anything else came out of a dependency, and the stage is what
 * keeps the answer machine-readable when that dependency's wording changes.
 */
async function inStage<T>(stage: RespondStage, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof PublisherError) throw error;
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
  const balanced = await inStage(RESPOND_STAGES.balance, () => ready.wallet.balance(proven));
  return inStage(RESPOND_STAGES.submit, () => ready.wallet.submit(balanced));
}

/** One link of a chain, rendered so neither its identity nor its text is lost. */
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
 * Render a thrown value as one line that NAMES the failure, causes innermost
 * last.
 *
 * `error.message` alone is not enough. The wallet works through Effect, which
 * rejects with a `FiberFailure` whose `name` is the ONLY place the failing class
 * survives: a live same-id race produced `(FiberFailure)
 * Wallet.InsufficientFunds: Insufficient Funds: could not balance dust`, and on
 * `message` alone the half naming WHICH constraint was hit is lost. `classify`
 * matches against this output, so this function is load-bearing for the error
 * codes, not just for the prose.
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
 * A 200 means the node reported the transaction finalized, which is equivalent
 * to `SucceedEntirely` here: both circuits run wholly in the guaranteed phase,
 * and a guaranteed-phase failure is rejected at pre-dispatch and never enters a
 * block. So inclusion is success and no confirming read is made.
 *
 * NOT SERIALIZED AND NOT RETRIED. Posts run concurrently and failures are
 * returned, so the caller owns the retry for two collisions:
 *
 * 1. One funding wallet, one spendable dust UTXO, so two concurrent posts
 *    collide at BALANCE time before either reaches the chain -> `wallet_unfunded`,
 *    recovering in about 35 seconds.
 * 2. Two posts under one request id both read the counter at N; the ledger's
 *    optimistic-concurrency check rejects the loser -> `state_conflict`, which
 *    never entered a block and was never charged.
 *
 * Whoever restores in-process serialization must keep the state reads INSIDE
 * whatever queue they add: reading first and queueing after lets the ledger
 * parameters go stale, which is rejected as `OutOfGas`.
 */
export async function handleRespond(config: Config, client: NodeClient, body: string): Promise<Reply> {
  const hidden = secrets(config);
  try {
    const validated = parseAndValidate(body);
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
    const safe = redact(failure.message, hidden);
    // A 400 is the caller's own request coming back at it and is not worth a log
    // line; everything else is this service failing to do its job.
    if (failure.code !== "bad_request") console.error(`respond failed [${failure.code}]: ${safe}`);
    return { status: statusFor(failure.code), body: errorBody(failure.code, safe) };
  }
}
