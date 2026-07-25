/**
 * `POST /respond`: validate, prove, pay, submit.
 *
 * MECHANISM, NEVER AUTHORITY. The signature was computed by the MPC threshold
 * before anything reached this service, and both circuits are blind appends.
 * `RespondRequestSchema` keeps malformed input away from the prover; it decides
 * nothing about who may write, and no check downstream of it does either.
 *
 * The escape hatch rather than `findDeployedContract`: three pinned reads, then
 * `createUnprovenCallTxFromInitialStates`, the stock proof provider, balance,
 * submit. The one entry point needing no `PublicDataProvider`, no indexer read,
 * no private-state provider.
 *
 * The request wire is frozen, pinned case for case by `tests/respond.test.ts`.
 * A 200 adds `tx_id` and `block_hash`; anything else is `{code, message}`.
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
import { z } from "zod";

import { type Config } from "./config.js";
import { describeFailure, fail, jsonObject, PublisherError, replyTo, type ErrorCode, type Reply } from "./errors.js";
import { assertLedgerTag, LEDGER_TAGS } from "./ledger.js";
import { fromHex, runtimeApiBytes, type BlockHashHex, type NodeClient } from "./node.js";
import { openFundingWallet } from "./wallet.js";

// ---- the wire contract -----------------------------------------------------

// One message per field: absent, `null`, the wrong type and the wrong value all
// read the same, because they are the same thing here. An absent key is the only
// way to omit an optional field; `null` rejects like any other wrong value.

const MUST_BE_AN_OBJECT = "must be an object";
const MUST_BE_HEX_32 = "must be 64 lowercase hex";
const MUST_BE_HEX_128 = "must be 256 lowercase hex (Bytes<128>)";
const MUST_BE_A_CIRCUIT = "must be postSignatureResponse or postRespondBidirectional";
const MUST_BE_ABSENT = "must be absent on postSignatureResponse";
const MUST_BE_AN_OUTPUT_LEN = "must be an integer in 0..=128";

const wireObject = <T extends z.ZodRawShape>(shape: T) => z.object(shape, MUST_BE_AN_OBJECT);

/** Bare lowercase hex: no `0x`, no uppercase. */
const wireHex = (bytes: number, message: string) =>
  z.string(message).regex(new RegExp(`^[0-9a-f]{${bytes * 2}}$`), message);

const hex32 = wireHex(32, MUST_BE_HEX_32);

/** A bidirectional field on the circuit that has none. */
const absent = z.undefined(MUST_BE_ABSENT).optional();

/**
 * The MPC's canonical `Signature { big_r, s, recovery_id }` verbatim, nested as
 * the Compact `Signature { bigR: { x, y }, s, recoveryId }` it lands in.
 * Coordinates and `s` are SEC1 BIG-ENDIAN hex, `recovery_id` the parity of R.y,
 * and the components reach the ledger untouched — the publisher converts nothing.
 */
const wireSignature = wireObject({
  big_r: wireObject({ x: hex32, y: hex32 }),
  s: hex32,
  recovery_id: z.literal([0, 1], "must be 0|1"),
});

/**
 * Unknown keys are stripped, never rejected. Field order is wire contract: only
 * the first issue is surfaced and zod reports them in declaration order, so a
 * caller fixing one field at a time walks them top to bottom. `circuit` is the
 * exception — as the discriminator it resolves before any other field, so an
 * unrecognized circuit answers even when the address is also wrong.
 */
const RespondRequestSchema = z.discriminatedUnion(
  "circuit",
  [
    wireObject({
      contract_address: hex32,
      circuit: z.literal("postSignatureResponse"),
      request_id: hex32,
      signature: wireSignature,
      serialized_output: absent,
      output_len: absent,
    }),
    wireObject({
      contract_address: hex32,
      circuit: z.literal("postRespondBidirectional"),
      request_id: hex32,
      signature: wireSignature,
      // Bytes<128>: the whole zero-padded ABI return data, not a digest of it.
      // The contract checks none of it; consumers verify on claim.
      serialized_output: wireHex(128, MUST_BE_HEX_128),
      output_len: z.int(MUST_BE_AN_OUTPUT_LEN).min(0, MUST_BE_AN_OUTPUT_LEN).max(128, MUST_BE_AN_OUTPUT_LEN),
    }),
  ],
  { error: MUST_BE_A_CIRCUIT },
);

/** Read off the schema, so the type cannot drift from what the parse accepts. */
export type RespondRequest = z.infer<typeof RespondRequestSchema>;
export type RespondCircuit = RespondRequest["circuit"];
export type WireSignature = RespondRequest["signature"];

// ---- parsing ---------------------------------------------------------------

/**
 * Deliberately not `jsonObject`'s `invalid JSON:`, which means the body was not
 * a JSON object at all; past that point the JSON is fine and the request is not.
 */
function toBadRequest(error: z.ZodError): PublisherError {
  const issue = error.issues[0]!;
  const path = issue.path.join(".");
  return new PublisherError("bad_request", `invalid request: ${path.length === 0 ? "" : `\`${path}\` `}${issue.message}`);
}

/** The only way in: what this returns is valid, so nothing downstream re-checks. */
export function parseRespondRequest(body: string): RespondRequest {
  const parsed = RespondRequestSchema.safeParse(jsonObject(body));
  if (!parsed.success) throw toBadRequest(parsed.error);
  return parsed.data;
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

/**
 * The wire signature as the events' `Signature` struct — the same shape under
 * the language's own naming, no transformation. Big-endian in, big-endian
 * stored: the publisher never touches byte order; consumers re-encode for
 * circuit args off-chain.
 */
function signatureStruct(signature: WireSignature): SignatureRespondedEvent["signature"] {
  return {
    bigR: { x: fromHex(signature.big_r.x), y: fromHex(signature.big_r.y) },
    s: fromHex(signature.s),
    recoveryId: BigInt(signature.recovery_id),
  };
}

export function respondCall(request: RespondRequest): RespondCall {
  const requestId = fromHex(request.request_id);
  if (request.circuit === "postSignatureResponse") {
    return {
      circuitId: "postSignatureResponse",
      args: [requestId, { signature: signatureStruct(request.signature) }],
    };
  }
  return {
    circuitId: "postRespondBidirectional",
    args: [
      requestId,
      {
        serializedOutput: fromHex(request.serialized_output),
        outputLen: BigInt(request.output_len),
        signature: signatureStruct(request.signature),
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
 * One budget for the whole post, because every dependency here waits forever by
 * default: a dead indexer never finishes wallet sync, `@polkadot/api` queues
 * across reconnects, and midnight-js's `submitTxCore` documents that it "waits
 * indefinitely". Unbounded, any of them holds the busy gate silently and answers
 * nobody. Longer than `RECIPE_TTL_MS`, so giving up strands no fee coin that
 * abandoning had not already stranded. Blowing it is fatal; see
 * {@link DeadlineExceeded}. Mutable as the test seam.
 */
export const RESPOND_TIMEOUT = { ms: 6 * 60 * 1000 };

/** Rejects with `onTimeout()` after `ms`. `Promise.race` handles the loser, so the abandoned attempt's own late failure surfaces nowhere. */
export async function withDeadline<T>(work: Promise<T>, ms: number, onTimeout: () => Error): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => void (timer = setTimeout(() => reject(onTimeout()), ms))),
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
  // Deliberately the operator's `managedDir`, not the contract package's own
  // asset resolution: anything else bypasses MIDNIGHT_PUB_MANAGED_DIR and guts
  // `assertCompiledContractMatches`'s "repoint it" remedy.
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
 * Lazy, and memoized even while pending: a boot that never settles is awaited by
 * every later request rather than started again, so a hung indexer costs one
 * wallet facade and not one per retry. A REJECTED boot clears the memo so the
 * next request tries afresh.
 */
function publisher(config: Config): Promise<Publisher> {
  publisherPromise ??= buildPublisher(config).catch((error: unknown) => {
    publisherPromise = undefined;
    throw error;
  });
  return publisherPromise;
}

/** Test seam: install a ready-made publisher, bypassing boot entirely. */
export function primePublisher(ready: Promise<Publisher>): void {
  publisherPromise = ready;
}

/** Back to boot state: the facade closed and the gate free. For shutdown, tests, and one-shot scripts. */
export async function closePublisher(): Promise<void> {
  const pending = publisherPromise;
  publisherPromise = undefined;
  inFlightRid = undefined;
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

  const options = createCallTxOptions(ready.compiledContract, call.circuitId, address, undefined, undefined, [
    call.args[0],
    call.args[1],
  ]);

  const unsubmitted = await createUnprovenCallTxFromInitialStates(
    ready.zkConfigProvider,
    { ...options, ...dependencies },
    ready.wallet.getEncryptionPublicKey(),
  );

  return ready.proofProvider.proveTx(unsubmitted.private.unprovenTx);
}

/** A substring that sharpens a step's default code into one the caller acts on differently. */
type Refinement = readonly [pattern: string, code: ErrorCode];

/** The dust shortfall the wallet reports two ways; either means back off, not that the request was wrong. */
const DUST_SHORTFALL: readonly Refinement[] = [
  ["Wallet.InsufficientFunds", "wallet_unfunded"],
  ["could not balance dust", "wallet_unfunded"],
];

/** Best-effort: `submissionService` flattens node errors, so this only surfaces in the rendered cause chain. */
const LOST_THE_RACE: readonly Refinement[] = [["ReadMismatch", "state_conflict"]];

/**
 * Names whatever a step threw: `code` is what failing there means, and the
 * refinements are the ONLY place this service matches on dependency error text.
 */
async function step<T>(code: ErrorCode, run: () => Promise<T>, refine: readonly Refinement[] = []): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof PublisherError) throw error;
    // The pinned reads are tag-checked before any deserializer runs, so a
    // version mismatch reaching here came out of a dependency's own blob:
    // name that, not the step it happened to surface in.
    if (isDeserializationError(error) && error.context.extracted?.receivedVersion !== undefined) {
      throw new PublisherError("ledger_mismatch", describeFailure(error));
    }
    const described = describeFailure(error);
    // Matched against a WIDER haystack than the answered message: Effect hides
    // the real cause on a Symbol that only `String` renders.
    const sharpened = refine.find(([pattern]) => `${described}\n${String(error)}`.includes(pattern))?.[1];
    throw new PublisherError(sharpened ?? code, described, { cause: error });
  }
}

/** What a completed post hands back: the wire answer, plus the block the reads were pinned to. */
interface Posted {
  readonly txId: string;
  readonly blockHash: string;
}

/** The whole post: boot, pinned reads, key check, prove, balance, submit. */
async function post(config: Config, client: NodeClient, request: RespondRequest): Promise<Posted> {
  const ready = await step("wallet_unsynced", () => publisher(config));
  const states = await step("node_unavailable", () => readCallStates(client, request.contract_address));
  assertCompiledContractMatches(ready, states.contractState, request.contract_address, config.managedDir);
  const call = respondCall(request);
  const proven = await step("prove_failed", () => proveCall(ready, call, request.contract_address, states));
  const balanced = await step("balance_failed", () => ready.wallet.balanceTx(proven), DUST_SHORTFALL);
  const txId = await step("submit_rejected", () => ready.wallet.submitTx(balanced), LOST_THE_RACE);
  return { txId, blockHash: states.blockHash.replace(/^0x/, "") };
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
/**
 * The one failure that ends the process. Nothing here is cancellable, so a post
 * that outlives its deadline keeps the gate AND keeps spending; the alternatives
 * are a second post racing it onto the wallet's one dust UTXO, or a gate wedged
 * until someone notices. Stopping is neither: the caller gets this answer, the
 * supervisor gets a clean restart.
 */
class DeadlineExceeded extends PublisherError {
  constructor(rid: string) {
    super(
      "internal",
      `respond exceeded the ${RESPOND_TIMEOUT.ms} ms deadline and the publisher is stopping; if it had ` +
        `reached submit the transaction may still land, so check the chain for rid ${rid} before retrying`,
    );
  }
}

export async function handleRespond(config: Config, client: NodeClient, body: string): Promise<Reply> {
  try {
    const request = parseRespondRequest(body);
    if (inFlightRid !== undefined) {
      return fail(
        "wallet_busy",
        `a respond for rid ${inFlightRid} holds the funding wallet; one post at a time, ~35s each`,
      );
    }
    inFlightRid = request.request_id;
    console.log(`respond: circuit=${request.circuit} rid=${request.request_id}`);
    const started = performance.now();
    const work = post(config, client, request);
    // The gate follows the WORK, not the answer: an abandoned post is still
    // spending, and releasing on the answer would put a second balance on the
    // coin it has not finished with.
    const release = (): void => {
      inFlightRid = undefined;
    };
    void work.then(release, release);
    const posted = await withDeadline(work, RESPOND_TIMEOUT.ms, () => new DeadlineExceeded(request.request_id));
    const elapsed = Math.round(performance.now() - started);
    console.log(`respond: rid=${request.request_id} submitted tx ${posted.txId} block ${posted.blockHash} in ${elapsed}ms`);
    return { status: 200, body: JSON.stringify({ status: "ok", tx_id: posted.txId, block_hash: posted.blockHash }) };
  } catch (error) {
    const reply = replyTo(error, "respond failed");
    return error instanceof DeadlineExceeded ? { ...reply, fatal: true } : reply;
  }
}
