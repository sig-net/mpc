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

import { type Config } from "./config.js";
import {
  badRequest,
  classify,
  failRedacted,
  jsonObject,
  PublisherError,
  RESPOND_STAGES,
  type Reply,
  type RespondStage,
} from "./errors.js";
import { assertLedgerTag, LEDGER_TAGS } from "./ledger.js";
import { fromHex, isHex, runtimeApiBytes, type BlockHashHex, type NodeClient } from "./node.js";
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
  // Finalized, not best: an orphaned block is state that never existed.
  const blockHash = (await client.rpc.chain.getFinalizedHead()).toHex();
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

// ---- deadlines ---------------------------------------------------------------

/**
 * Hangs, not latencies: a dead indexer leaves the wallet sync pending forever,
 * and a node that dies mid-life leaves `@polkadot/api` queueing calls for a
 * reconnect that may never come. Without these, the caller's `POST /respond`
 * simply never answers, which is the one failure the error model cannot
 * express. balance and submit are deliberately NOT bounded: abandoning a
 * finalized recipe strands the fee coin for the dust-intent TTL (`wallet.ts`).
 *
 * Fields are mutable on purpose, as the test seam that lets a suite shrink a
 * deadline instead of waiting one out.
 */
export const RESPOND_DEADLINES = {
  /** First respond after boot pays for wallet sync; generous. */
  boot: 90_000,
  /** Three runtime-API reads over an open socket; anything near this is a hang. */
  read: 15_000,
  /** Proof-server p50 is ~0.4s; this covers a queue, not a hang. */
  prove: 60_000,
};

/** Rejects with `timeoutError()` after `ms`; the abandoned attempt's own late failure is swallowed. */
export async function withDeadline<T>(work: Promise<T>, ms: number, timeoutError: () => Error): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          work.catch(() => undefined);
          reject(timeoutError());
        }, ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

// ---- the publisher: wallet, keys, proof server -----------------------------

/** Whatever {@link buildPublisher} assembles; stated once, there. */
export type Publisher = Readonly<Awaited<ReturnType<typeof buildPublisher>>>;

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

/**
 * Lazy: a failed OR timed-out attempt clears the memo so the next request
 * retries. On timeout the build keeps running in the background; if it ever
 * resolves it closes itself, so a timed-out boot cannot leak a synced facade.
 */
function publisher(config: Config): Promise<Publisher> {
  if (publisherPromise === undefined) {
    const building = buildPublisher(config);
    publisherPromise = withDeadline(building, RESPOND_DEADLINES.boot, () => {
      void building.then((late) => late.wallet.close()).catch(() => undefined);
      return new PublisherError(
        "wallet_unsynced",
        `publisher boot exceeded ${RESPOND_DEADLINES.boot} ms: the funding wallet could not sync. ` +
          `Is the indexer at ${config.indexerUrl} reachable? Retry once it is.`,
        "boot",
      );
    }).catch((error: unknown) => {
      publisherPromise = undefined;
      throw error;
    });
  }
  return publisherPromise;
}

/** Test seam: install a ready-made publisher, bypassing boot entirely. */
export function primePublisher(ready: Promise<Publisher>): void {
  publisherPromise = ready;
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

/** A {@link PublisherError} passes through, gaining the stage if it lacks one; anything else is named by its stage. */
async function inStage<T>(stage: RespondStage, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof PublisherError) {
      throw error.stage === undefined ? new PublisherError(error.code, error.message, stage.name) : error;
    }
    // A deserialization failure is NOT an unreachable node, which is what the
    // read stage's fallback would otherwise call it — telling the caller to
    // retry a condition no amount of retrying resolves.
    if (isDeserializationError(error) && error.context.extracted?.receivedVersion !== undefined) {
      throw new PublisherError("ledger_mismatch", describeFailure(error), stage.name);
    }
    const described = describeFailure(error);
    // Classified against a WIDER haystack than the message it answers with.
    // Effect's `FiberFailure` keeps its cause on a Symbol, not on `.cause`, so
    // `describeFailure`'s walk cannot reach it and every submit failure renders
    // as the same constant `SubmissionError: Transaction submission error`.
    // `String(error)` runs Effect's own `Cause.pretty` and does render the
    // nested chain. It is multi-line with stack frames, so it is fit for
    // matching and not for a response body.
    throw new PublisherError(classify(stage, `${described}\n${String(error)}`), described, stage.name);
  }
}

/** What a completed post hands back: the wire answer plus the ops log line. */
interface Posted {
  readonly txId: string;
  /** The finalized block the three reads were pinned to, bare hex. */
  readonly blockHash: string;
  /** `read=12ms prove=350ms ...`, one token per stage. */
  readonly timing: string;
}

/** The whole post: pinned reads, key check, prove, balance, submit. */
async function post(
  config: Config,
  client: NodeClient,
  ready: Publisher,
  request: ValidatedRespondRequest,
): Promise<Posted> {
  const timings: string[] = [];
  const timed = async <T>(stage: RespondStage, run: () => Promise<T>): Promise<T> => {
    const started = performance.now();
    try {
      return await inStage(stage, run);
    } finally {
      timings.push(`${stage.name}=${Math.round(performance.now() - started)}ms`);
    }
  };

  const deadline = (what: string, ms: number) => () => new Error(`${what} exceeded the ${ms} ms deadline`);
  const states = await timed(RESPOND_STAGES.read, () =>
    withDeadline(readCallStates(client, request.contract_address), RESPOND_DEADLINES.read, deadline("reading the pinned states", RESPOND_DEADLINES.read)));
  assertCompiledContractMatches(ready, states.contractState, request.contract_address, config.managedDir);
  const call = respondCall(request);
  const proven = await timed(RESPOND_STAGES.prove, () =>
    withDeadline(proveCall(ready, call, request.contract_address, states), RESPOND_DEADLINES.prove, deadline("proving", RESPOND_DEADLINES.prove)));
  // No deadline past this point: abandoning a finalized recipe strands the fee
  // coin for the dust-intent TTL (`wallet.ts`), so balance and submit run out.
  const balanced = await timed(RESPOND_STAGES.balance, () => ready.wallet.balanceTx(proven));
  const txId = await timed(RESPOND_STAGES.submit, () => ready.wallet.submitTx(balanced));
  return { txId, blockHash: states.blockHash.replace(/^0x/, ""), timing: timings.join(" ") };
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

/** The request id currently holding the wallet, from boot-or-read through submit. */
let inFlightRid: string | undefined;

/**
 * A 200 means finalized, equivalent to `SucceedEntirely` here: both circuits run
 * wholly in the guaranteed phase, so inclusion is success. The body carries the
 * submitted `tx_id` and the `block_hash` the reads were pinned to, for
 * settlement observation and debugging.
 *
 * ONE AT A TIME, NOT QUEUED: the wallet has a single dust UTXO, so a second
 * concurrent post could only burn a prove and then fail at balance ~35s of
 * recovery later. It is answered `wallet_busy` up front instead; retrying when
 * the first answers is the caller's job. Same-rid duplicates still lose the
 * ledger's optimistic-concurrency check (`state_conflict`, never charged).
 * Anyone replacing this with a queue must keep the state reads inside it, or
 * the parameters go stale.
 */
export async function handleRespond(config: Config, client: NodeClient, body: string): Promise<Reply> {
  let claimed = false;
  try {
    const validated = parseRespondRequest(body);
    validateRespondRequest(validated);
    if (inFlightRid !== undefined) {
      return failRedacted(
        "wallet_busy",
        `a respond for rid ${inFlightRid} holds the funding wallet; one post at a time, ~35s each`,
        [config.fundingSeed],
      );
    }
    inFlightRid = validated.request_id;
    claimed = true;
    console.log(`respond: circuit=${validated.circuit} rid=${validated.request_id}`);
    // Boot failures other than the sync deadline stay unstaged `internal`: an
    // unreadable `managedDir` or a bad seed is this service failing to start,
    // which no stage code describes better than the message itself.
    const ready = await publisher(config);
    const posted = await post(config, client, ready, validated);
    console.log(`respond: rid=${validated.request_id} submitted tx ${posted.txId} block ${posted.blockHash} ${posted.timing}`);
    return { status: 200, body: JSON.stringify({ status: "ok", tx_id: posted.txId, block_hash: posted.blockHash }) };
  } catch (error) {
    // Redacted at the source: wallet, proof-server and node errors can echo
    // values they were handed, and this text becomes both a response body and a
    // log line. `failRedacted` is the single funnel; the seed never survives it.
    const failure = error instanceof PublisherError ? error : new PublisherError("internal", describeFailure(error));
    return failRedacted(failure.code, failure.message, [config.fundingSeed], "respond failed", failure.stage);
  } finally {
    if (claimed) inFlightRid = undefined;
  }
}
