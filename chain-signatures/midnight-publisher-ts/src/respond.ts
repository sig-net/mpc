/**
 * `POST /respond`: the write seam. Validate an already-computed response, prove
 * it, pay for it, and put it on chain.
 *
 * MECHANISM, NEVER AUTHORITY. The signature in the request was computed by the
 * MPC threshold before anything reached this service; both circuits are blind
 * appends (counter increment plus map insert, no assert), so nothing here
 * decides whether a response is legitimate. The validation below is a shape
 * check that keeps malformed input from reaching the prover, not an
 * authorization check.
 *
 * The route is the escape hatch rather than `findDeployedContract`: three
 * runtime-API reads at one pinned finalized block, then
 * `createUnprovenCallTxFromInitialStates` with `crossContract` omitted, then the
 * stock `httpClientProofProvider`, then balance and submit through the wallet.
 * That needs no `PublicDataProvider`, no indexer on the read side, and no
 * private-state provider at all (the initial private state is passed inline),
 * so no directory is created and no database handle is taken.
 *
 * What skipping `findDeployedContract` gives up is its `verifyContractState`
 * check, so a stale `MIDNIGHT_PUB_MANAGED_DIR` would otherwise produce a
 * chain-rejected proof instead of a clear client-side error. That check is
 * reproduced explicitly below, against the same contract state the call is
 * built from, so it costs no extra read.
 *
 * CIRCUIT NAMES. The deployed contract declares `postSignatureResponse` and
 * `postRespondBidirectional`, and `doc/midnight-spec.md` agrees. The Rust
 * implementation this replaces still validates the older spelling
 * `postRespond`, which no longer exists on chain and could only ever produce a
 * proving failure. This implementation accepts the contract's names, so
 * `postRespond` is rejected as an unknown circuit, and the four 400 messages
 * that embed the circuit name are respelled with it. Everything else on the
 * wire (field names, optionality, lengths, the lowercase-hex rule,
 * cross-circuit exclusion, the `recovery_id` and `output_len` ranges, every
 * other message verbatim, and the order the checks run in) is byte-identical to
 * the Rust rules.
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
import { fromHex, isHex, resolveAnchor, runtimeApiBytes, type BlockHashHex, type NodeClient } from "./node.js";
import { openFundingWallet, type FundingWallet } from "./wallet.js";
import type { Reply } from "./server.js";

// ---- the wire contract -----------------------------------------------------

/**
 * The `POST /respond` body. Mirror of the Rust `RespondRequest`, field names and
 * optionality included: the two implementations cannot share a type, so the
 * JSON contract is pinned by identical fixtures on both sides.
 *
 * `sig_r` and `sig_s` are LITTLE-ENDIAN, the byte order the record's
 * `Bytes<32>` fields store; the node-side client byte-reverses k256's big-endian
 * scalars before posting. `serialized_output` is the WHOLE ABI-encoded return
 * data (`Bytes<128>`, zero-padded, so 256 hex) plus its meaningful byte count,
 * not a digest of it. The contract checks none of this: consumers verify on
 * claim, and validity is the caller's responsibility.
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

/**
 * The two circuits this seam posts to, narrowed against the generated contract
 * so a rename upstream becomes a compile error here rather than a proving
 * failure at run time.
 */
export const RESPOND_CIRCUITS = ["postSignatureResponse", "postRespondBidirectional"] as const satisfies readonly SignetContractCircuitId[];

/** One of {@link RESPOND_CIRCUITS}. */
export type RespondCircuit = (typeof RESPOND_CIRCUITS)[number];

/**
 * A request that has passed {@link validateRespondRequest}: the circuit is one
 * of the two postable ones, and exactly the fields that circuit needs are known
 * to be present. Making the guarantee a type is what keeps {@link respondCall}
 * free of non-null assertions.
 */
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

/** A validation failure: HTTP 400, with the message as the whole body. */
export class RespondRequestError extends Error {}

// ---- parsing and validation ------------------------------------------------

/** Whether a JSON value is absent for an optional field. Rust's serde treats `null` and a missing key alike. */
function absent(value: unknown): boolean {
  return value === undefined || value === null;
}

function requiredString(source: Record<string, unknown>, field: string): string {
  const value = source[field];
  if (typeof value === "string") return value;
  throw new RespondRequestError(
    absent(value) ? `invalid JSON: missing field \`${field}\`` : `invalid JSON: \`${field}\` must be a string`,
  );
}

function optionalString(source: Record<string, unknown>, field: string): string | undefined {
  const value = source[field];
  if (absent(value)) return undefined;
  if (typeof value === "string") return value;
  throw new RespondRequestError(`invalid JSON: \`${field}\` must be a string`);
}

/** An optional `u8`, matching the Rust field type: an integer in 0..=255 or absent. */
function optionalByte(source: Record<string, unknown>, field: string): number | undefined {
  const value = source[field];
  if (absent(value)) return undefined;
  if (typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 255) return value;
  throw new RespondRequestError(`invalid JSON: \`${field}\` must be an integer in 0..=255`);
}

/**
 * Parse a request body into a {@link RespondRequest}.
 *
 * Unknown fields are ignored, matching the Rust struct, which does not set
 * `deny_unknown_fields`.
 *
 * @param body - The raw request body.
 * @returns The parsed request, not yet validated.
 * @throws {@link RespondRequestError} If the body is not a JSON object, or a
 *   field has the wrong JSON type. The message is prefixed `invalid JSON:`, as
 *   the Rust implementation's is.
 */
export function parseRespondRequest(body: string): RespondRequest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (error) {
    throw new RespondRequestError(`invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new RespondRequestError("invalid JSON: expected a JSON object");
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

/** True when the field is present and exactly 32 bytes of lowercase hex. */
function isHex32(value: string | undefined): boolean {
  return value !== undefined && isHex(value, 32);
}

/**
 * Validate a parsed request. The checks and their order are byte-identical to
 * the Rust `validate`, so the same body yields the same 400 body.
 *
 * @param request - The parsed request.
 * @throws {@link RespondRequestError} On the first rule that fails.
 */
export function validateRespondRequest(request: RespondRequest): asserts request is ValidatedRespondRequest {
  if (!isHex(request.contract_address, 32)) {
    throw new RespondRequestError("contract_address must be 64 lowercase hex");
  }
  if (!isHex(request.request_id, 32)) {
    throw new RespondRequestError("request_id must be 64 hex");
  }

  switch (request.circuit) {
    case "postSignatureResponse": {
      if (!(isHex32(request.big_r_x) && isHex32(request.big_r_y) && isHex32(request.s))) {
        throw new RespondRequestError("postSignatureResponse needs big_r_x/big_r_y/s as 64 lowercase hex each");
      }
      if (!(request.recovery_id !== undefined && request.recovery_id <= 1)) {
        throw new RespondRequestError("postSignatureResponse recovery_id must be 0|1");
      }
      if (
        request.serialized_output !== undefined ||
        request.output_len !== undefined ||
        request.sig_r !== undefined ||
        request.sig_s !== undefined
      ) {
        throw new RespondRequestError("postSignatureResponse takes no bidirectional fields");
      }
      return;
    }
    case "postRespondBidirectional": {
      // serialized_output is Bytes<128>: the whole zero-padded ABI return data,
      // not a digest of it.
      if (!(request.serialized_output !== undefined && isHex(request.serialized_output, 128))) {
        throw new RespondRequestError(
          "postRespondBidirectional needs serialized_output as 256 lowercase hex (Bytes<128>)",
        );
      }
      if (!(request.output_len !== undefined && request.output_len <= 128)) {
        throw new RespondRequestError("postRespondBidirectional output_len must be 0..=128");
      }
      if (!(isHex32(request.sig_r) && isHex32(request.sig_s))) {
        throw new RespondRequestError("postRespondBidirectional needs sig_r/sig_s as 64 lowercase hex each");
      }
      if (!(request.recovery_id !== undefined && request.recovery_id <= 1)) {
        throw new RespondRequestError("postRespondBidirectional recovery_id must be 0|1");
      }
      if (request.big_r_x !== undefined || request.big_r_y !== undefined || request.s !== undefined) {
        throw new RespondRequestError("postRespondBidirectional takes no postSignatureResponse fields");
      }
      return;
    }
    default:
      throw new RespondRequestError(`unknown circuit ${request.circuit}`);
  }
}

/**
 * Parse and validate in one step, so the narrowing the assertion performs
 * survives into the caller.
 *
 * @param body - The raw request body.
 * @returns The validated request.
 * @throws {@link RespondRequestError} On the first parse or validation failure.
 */
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
 * A validated request reduced to the exact arguments its circuit takes.
 *
 * Both circuits take two arguments, the request id then the whole event struct,
 * because that is what the Compact contract declares. Under the retired toolkit
 * this was a JSON5 argv codec with number-versus-string and arity hazards; here
 * the generated types make a wrong shape a compile error.
 */
export type RespondCall =
  | { readonly circuitId: "postSignatureResponse"; readonly args: readonly [Uint8Array, SignatureRespondedEvent] }
  | { readonly circuitId: "postRespondBidirectional"; readonly args: readonly [Uint8Array, RespondBidirectionalEvent] };

/**
 * Build the circuit arguments for a validated request.
 *
 * `sig_r`/`sig_s` are passed through unreversed: they are already the
 * little-endian order the hub circuit's `Bytes<32> as Secp256k1Scalar` cast
 * expects.
 *
 * @param request - A request that has passed {@link validateRespondRequest}.
 * @returns The circuit id and its two arguments.
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

/**
 * Assert a runtime-API payload carries the self-describing tag it should,
 * before it is deserialized.
 *
 * COMPLEMENTARY TO the `deserialize*` wrappers below, not redundant with them.
 * They classify what the ledger can see: a version or format mismatch in the
 * bytes. This fires first and names a cause they cannot know, because it is a
 * `@polkadot/api` gotcha rather than a ledger one: a wrong-looking tag means
 * the runtime-API ARGUMENT encoding was wrong, not that the deserializer is
 * broken. `@polkadot/api` treats a `Uint8Array` as already SCALE-encoded and
 * compact-decodes its head as a length, so an address passed as bytes rather
 * than as `0x`-prefixed hex fails with a message about a length. Naming the
 * real cause here saves that hunt.
 *
 * @param bytes - The raw payload.
 * @param tag - The tag it must carry, searched for in the leading 64 bytes,
 *   since it sits at or very near the front.
 * @param what - The payload's name, for the message.
 * @throws If the tag is absent.
 */
function assertLedgerTag(bytes: Uint8Array, tag: string, what: string): void {
  const head = Buffer.from(bytes.subarray(0, 64)).toString("latin1");
  if (head.includes(tag)) return;
  throw new Error(
    `${what} does not look like a ${tag} blob (leading bytes: ${JSON.stringify(head.slice(0, 48))}). ` +
      `A wrong leading tag means the runtime-API ARGUMENT encoding is wrong, not the deserializer: ` +
      `addresses must be passed as 0x-prefixed hex strings, never as Uint8Array.`,
  );
}

/** The three states a call is built from, all read at one pinned finalized block. */
interface CallStates {
  readonly blockHash: BlockHashHex;
  readonly contractState: ContractState;
  readonly zswapChainState: ZswapChainState;
  readonly ledgerParameters: LedgerParameters;
}

/**
 * Read the contract state, the zswap chain state and the live ledger parameters
 * at the finalized head.
 *
 * All three are pinned to one block hash. The ledger parameters are genuinely
 * load-bearing rather than a formality: substituting
 * `LedgerParameters.initialParameters()` gets the transaction rejected with
 * `Transcript(Execution(OutOfGas))`, because fee and price adjustment drift per
 * block.
 *
 * @param client - The node client.
 * @param address - Bare 64-hex contract address.
 * @returns The three states plus the block they were read at.
 * @throws If the node cannot serve one of them, naming which.
 */
async function readCallStates(client: NodeClient, address: string): Promise<CallStates> {
  const { blockHash } = await resolveAnchor(client, undefined);
  const [rawContract, rawZswap, rawParams] = await Promise.all([
    runtimeApiBytes(client, blockHash, "getContractState", `0x${address}`),
    runtimeApiBytes(client, blockHash, "getZswapChainState", `0x${address}`),
    runtimeApiBytes(client, blockHash, "getLedgerParameters"),
  ]);

  if (rawContract === undefined) {
    throw new Error(`no contract state at ${address} in block ${blockHash} (is the contract deployed?)`);
  }
  if (rawZswap === undefined) throw new Error(`no zswap chain state for ${address} in block ${blockHash}`);
  if (rawParams === undefined) throw new Error(`node returned no ledger parameters at block ${blockHash}`);

  assertLedgerTag(rawContract, "midnight:contract-state[v8]", "contract state");
  assertLedgerTag(rawZswap, "midnight:zswap-ledger-state[v5]", "zswap chain state");
  assertLedgerTag(rawParams, "midnight:ledger-parameters[v8]", "ledger parameters");

  const ctx = { caller: "midnight-publisher:readCallStates" };
  return {
    blockHash,
    // The three wrappers are NOT interchangeable, and the tuple looks
    // homogeneous while it is not. `deserializeCompactContractState` yields
    // onchain-runtime-v4's `ContractState`; the ledger-named
    // `deserializeContractState` beside it yields ledger-v9's, which is the
    // wrong class here and produces the classic dual-WASM-instance "expected
    // instance of" failure. `ZswapChainState` and `LedgerParameters` are
    // ledger-v9's, so those two take the ledger wrappers.
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
 * The process's single publisher, built on first use.
 *
 * Lazy rather than built at startup so the read seams stay available when the
 * indexer or the proof server is down, and so a transient failure here does not
 * permanently poison the process: a failed attempt clears the memo and the next
 * request retries.
 *
 * @param config - Validated configuration.
 * @returns The publisher.
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

/**
 * Release the funding wallet and forget the memoized publisher. For tests and
 * one-shot scripts; the service itself holds it for the process's lifetime.
 *
 * @returns Once the wallet has stopped, or immediately when none was opened.
 */
export async function closePublisher(): Promise<void> {
  const pending = publisherPromise;
  publisherPromise = undefined;
  if (pending === undefined) return;
  await pending.then((ready) => ready.wallet.close()).catch(() => undefined);
}

/**
 * Reproduce `findDeployedContract`'s `verifyContractState` check, which the
 * escape-hatch route skips.
 *
 * Without it a stale `MIDNIGHT_PUB_MANAGED_DIR` is only discovered when the
 * chain rejects the finished proof, which costs a prove, a fee-balancing round
 * and an opaque error. Run against the same contract state the call is built
 * from, so it costs no extra read, and run every time rather than once, so a
 * redeploy under a running service is caught immediately.
 *
 * @param ready - The publisher, holding the local verifier keys.
 * @param state - The deployed contract's state, freshly read.
 * @param address - The contract address, for the error message.
 * @param managedDir - The compiled-asset root, for the error message.
 * @throws If any circuit is absent from the deployed contract or has a
 *   different verifier key, naming the circuits that differ.
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
      throw new Error(
        `compiled contract in ${managedDir} does not match the contract deployed at ${address}: ` +
          `verifier keys differ or are absent for [${error.circuitIds.join(", ")}]. ` +
          `A proof built here would be rejected by the chain. Rebuild the contract assets, or point ` +
          `MIDNIGHT_PUB_MANAGED_DIR at the assets this contract was deployed from.`,
      );
    }
    throw error;
  }
}

// ---- concurrency -----------------------------------------------------------

/**
 * Every fee-paying post runs in this queue, one at a time.
 *
 * Two independent constraints force it, and both were measured rather than
 * assumed:
 *
 * 1. ONE WALLET IS ONE IN-FLIGHT FEE-PAYING TRANSACTION. Fees are paid in DUST,
 *    and every wallet on this chain holds exactly one spendable dust UTXO, so a
 *    second concurrent balance fails with the misleading
 *    `Wallet.InsufficientFunds: could not balance dust` despite a large
 *    balance. This service holds one wallet, so the queue is global. Scaling
 *    out means one wallet per worker, at which point this becomes per-wallet.
 * 2. SAME-REQUEST-ID POSTS CANNOT BE PARALLELISED. A call's transcript pins the
 *    cells it read, so two posts under one request id both read the counter at
 *    N, the winner makes it N+1, and the loser is rejected with
 *    `Transcript(Execution(ReadMismatch))`. Serializing per request id is
 *    therefore mandatory; a single global queue is strictly stronger and
 *    subsumes it.
 *
 * The three state reads happen INSIDE the queue, not before it. Reading first
 * and queueing after would let the ledger parameters go stale while waiting,
 * and stale parameters get the transaction rejected with
 * `Transcript(Execution(OutOfGas))` because fees drift per block.
 *
 * No throughput is lost by being global: a single wallet cannot have two
 * fee-paying transactions in flight in the first place.
 */
let walletQueue: Promise<void> = Promise.resolve();

function queued<T>(run: () => Promise<T>): Promise<T> {
  // `.then(run, run)` rather than `.then(run)`: the predecessor's outcome must
  // never decide whether this request runs.
  const settled = walletQueue.then(run, run);
  walletQueue = settled.then(
    () => undefined,
    () => undefined,
  );
  return settled;
}

/** Attempts for one post, the first included. */
const MAX_ATTEMPTS = 5;

/** Backoff base. Roughly a block time, which is when the contended cell can next change. */
const RETRY_BASE_MS = 1_000;

/**
 * True when the node rejected the transaction as invalid, which for these
 * blind-append circuits means the ledger-level optimistic-concurrency check
 * lost: another post under the same request id moved the counter between our
 * read and our dispatch.
 *
 * Cheap to retry, because a loser is rejected at pre-dispatch in the guaranteed
 * phase: it is never included in a block and never charged a fee.
 *
 * @param error - The thrown value.
 * @returns Whether a fresh read and a rebuilt proof could succeed.
 */
export function isRetryableSubmission(error: unknown): boolean {
  for (let current: unknown = error, depth = 0; current !== undefined && current !== null && depth < 8; depth += 1) {
    if (typeof current !== "object") break;
    const tag = (current as { _tag?: unknown })._tag;
    if (tag === "TransactionInvalidError") return true;
    current = (current as { cause?: unknown }).cause;
  }
  return error instanceof Error && error.message.includes("TransactionInvalidError");
}

/**
 * Full-jitter backoff. The jitter is not decoration: lockstep retries re-collide
 * on the same cell, and a measured three-way same-id burst livelocked with
 * fixed delays while the winner succeeded on its first attempt.
 *
 * @param attempt - Zero-based attempt index that just failed.
 * @returns Milliseconds to wait.
 */
export function backoffMs(attempt: number): number {
  return Math.random() * RETRY_BASE_MS * 2 ** attempt;
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

// ---- the flow --------------------------------------------------------------

/**
 * Build and prove the call. Returns the proven, still unbalanced transaction.
 *
 * The branch on circuit id is what keeps the argument tuple typed: each arm
 * calls `createCallTxOptions` with a literal circuit id, so the generated
 * parameter types apply.
 */
async function proveCall(ready: Publisher, call: RespondCall, address: string, states: CallStates): Promise<UnboundTransaction> {
  const dependencies = {
    coinPublicKey: ready.wallet.coinPublicKey,
    initialContractState: states.contractState,
    initialZswapChainState: states.zswapChainState,
    ledgerParameters: states.ledgerParameters,
    // Passed inline, which is why this route needs no private-state provider at
    // all: nothing is stored, nothing is read, and no directory is created. The
    // contract declares no witnesses, so this empty record is never consulted.
    initialPrivateState: createSignetContractPrivateState(),
  };

  // The ternary is not cosmetic: `createCallTxOptions` types its `args` against
  // the circuit id, so each arm must pass a literal id for the generated
  // parameter types to apply. `crossContract` is omitted, which is what lets the
  // whole route run without a `PublicDataProvider`.
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

/** One full attempt: pinned reads, key check, prove, balance, submit. */
async function postOnce(
  config: Config,
  client: NodeClient,
  ready: Publisher,
  request: ValidatedRespondRequest,
): Promise<string> {
  const states = await readCallStates(client, request.contract_address);
  assertCompiledContractMatches(ready, states.contractState, request.contract_address, config.managedDir);
  const proven = await proveCall(ready, respondCall(request), request.contract_address, states);
  const balanced = await ready.wallet.balance(proven);
  return ready.wallet.submit(balanced);
}

/**
 * `POST /respond`: validate, prove and submit one response.
 *
 * A 200 means the node reported the transaction finalized. That is equivalent
 * to `SucceedEntirely` for this contract: both circuits run wholly in the
 * guaranteed phase, and a guaranteed-phase failure is rejected at pre-dispatch
 * and never included in a block. So inclusion is success, and no extra
 * confirming read is made, matching the Rust implementation's contract.
 *
 * @param config - Validated configuration.
 * @param client - Connected node client, used for the three pinned state reads.
 * @param body - The raw request body.
 * @returns 200 `{"status":"ok"}`, 400 with the validation message, or 502 with
 *   a redacted failure description.
 */
export async function handleRespond(config: Config, client: NodeClient, body: string): Promise<Reply> {
  let validated: ValidatedRespondRequest;
  try {
    validated = parseAndValidate(body);
  } catch (error) {
    if (error instanceof RespondRequestError) return { code: 400, body: error.message };
    throw error;
  }

  console.log(`respond: circuit=${validated.circuit} rid=${validated.request_id}`);

  const hidden = secrets(config);
  try {
    const ready = await publisher(config);
    const txId = await queued(async () => {
      for (let attempt = 0; ; attempt += 1) {
        try {
          return await postOnce(config, client, ready, validated);
        } catch (error) {
          if (attempt + 1 >= MAX_ATTEMPTS || !isRetryableSubmission(error)) throw error;
          const wait = backoffMs(attempt);
          console.warn(
            `respond: rid=${validated.request_id} lost the ledger-level race, retrying in ${Math.round(wait)} ms ` +
              `(attempt ${attempt + 2}/${MAX_ATTEMPTS})`,
          );
          await sleep(wait);
        }
      }
    });
    console.log(`respond: rid=${validated.request_id} submitted tx ${txId}`);
    return { code: 200, body: `{"status":"ok"}` };
  } catch (error) {
    // Redacted at the source: wallet, proof-server and node errors can echo
    // values they were handed, and this text becomes both a 502 body and a log
    // line. The funding seed must never survive the trip.
    const safe = redact(error instanceof Error ? error.message : String(error), hidden);
    console.error(`respond failed: ${safe}`);
    return { code: 502, body: safe };
  }
}
