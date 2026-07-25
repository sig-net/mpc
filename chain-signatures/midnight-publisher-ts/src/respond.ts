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
 * Replies extend it: `stage` on errors, `tx_id`/`block_hash` on 200.
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
 * The MPC's canonical `Signature { big_r, s, recovery_id }` verbatim, nested
 * exactly as every other sig-net signer represents it (the Rust type, the EVM
 * and Solana contracts, the Canton parser, and the Compact
 * `Signature { bigR: { x, y }, s, recoveryId }` this lands in). Coordinates
 * and `s` are SEC1 BIG-ENDIAN hex, `recovery_id` the parity of R.y, and the
 * components reach the ledger untouched — the publisher converts nothing.
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
  return badRequest(`invalid request: ${path.length === 0 ? "" : `\`${path}\` `}${issue.message}`);
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
 * Per-stage time budgets, applied by `post`'s `runStage`; a stage absent here
 * runs unbounded. They bound hangs, not latencies: a dead indexer leaves wallet sync
 * pending forever and `@polkadot/api` queues calls across reconnects
 * indefinitely, and midnight-js's own `submitTxCore` documents that it "waits
 * indefinitely", which a service holding the busy gate cannot afford. balance
 * and submit are deliberately absent: abandoning a finalized recipe strands the
 * fee coin for the dust-intent TTL (`wallet.ts`). Mutable as the test seam.
 */
export const RESPOND_DEADLINES: { boot: number } & Partial<Record<string, number>> = {
  /** First respond after boot pays for wallet sync; generous. */
  boot: 90_000,
  /** Three runtime-API reads over an open socket; anything near this is a hang. */
  read: 15_000,
  /** Proof-server p50 is ~0.4s; this covers a queue, not a hang. */
  prove: 60_000,
};

/** Rejects after `ms` (a `what` string becomes a plain deadline `Error`); the abandoned attempt's own late failure is swallowed. */
export async function withDeadline<T>(work: Promise<T>, ms: number, onTimeout: string | (() => Error)): Promise<T> {
  const timeoutError = typeof onTimeout === "string" ? () => new Error(`${onTimeout} exceeded the ${ms} ms deadline`) : onTimeout;
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

/**
 * The failure's rendered cause chain as wire evidence, when it says more than
 * the one-line message: Effect's `FiberFailure` hides its cause on a Symbol
 * where `describeFailure` cannot reach it, while `String(error)` runs
 * `Cause.pretty` and renders the whole chain. Stack frames stripped, capped;
 * single-line renderings carry nothing `describeFailure` did not already say.
 */
function failureDetail(error: unknown): string | undefined {
  const lines = String(error)
    .split("\n")
    .filter((line) => !/^\s+at /.test(line) && line.trim().length > 0);
  if (lines.length <= 1) return undefined;
  const rendered = lines.join("\n");
  return rendered.length > 2_000 ? `${rendered.slice(0, 2_000)}…` : rendered;
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
    // Classified against a WIDER haystack than the answered message, for the
    // same Symbol-hidden-cause reason `failureDetail` exists; the caller gets
    // the same evidence in `detail`.
    throw new PublisherError(classify(stage, `${described}\n${String(error)}`), described, stage.name, failureDetail(error));
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
  request: RespondRequest,
): Promise<Posted> {
  /** Classifies (`inStage`), bounds (`RESPOND_DEADLINES`), and clocks one stage. */
  const timings: string[] = [];
  const runStage = async <T>(stage: RespondStage, run: () => Promise<T>): Promise<T> => {
    const budget = RESPOND_DEADLINES[stage.name];
    const started = performance.now();
    try {
      return await inStage(stage, budget === undefined ? run : () => withDeadline(run(), budget, stage.name));
    } finally {
      timings.push(`${stage.name}=${Math.round(performance.now() - started)}ms`);
    }
  };

  const states = await runStage(RESPOND_STAGES.read, () => readCallStates(client, request.contract_address));
  assertCompiledContractMatches(ready, states.contractState, request.contract_address, config.managedDir);
  const call = respondCall(request);
  const proven = await runStage(RESPOND_STAGES.prove, () => proveCall(ready, call, request.contract_address, states));
  const balanced = await runStage(RESPOND_STAGES.balance, () => ready.wallet.balanceTx(proven));
  const txId = await runStage(RESPOND_STAGES.submit, () => ready.wallet.submitTx(balanced));
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
    const request = parseRespondRequest(body);
    if (inFlightRid !== undefined) {
      return failRedacted(
        "wallet_busy",
        `a respond for rid ${inFlightRid} holds the funding wallet; one post at a time, ~35s each`,
        [config.fundingSeed],
      );
    }
    inFlightRid = request.request_id;
    claimed = true;
    console.log(`respond: circuit=${request.circuit} rid=${request.request_id}`);
    // Boot failures other than the sync deadline stay unstaged `internal`: an
    // unreadable `managedDir` or a bad seed is this service failing to start,
    // which no stage code describes better than the message itself.
    const ready = await publisher(config);
    const posted = await post(config, client, ready, request);
    console.log(`respond: rid=${request.request_id} submitted tx ${posted.txId} block ${posted.blockHash} ${posted.timing}`);
    return { status: 200, body: JSON.stringify({ status: "ok", tx_id: posted.txId, block_hash: posted.blockHash }) };
  } catch (error) {
    // Redacted at the source: wallet, proof-server and node errors can echo
    // values they were handed, and this text becomes both a response body and a
    // log line. `failRedacted` is the single funnel; the seed never survives it.
    const failure = error instanceof PublisherError ? error : new PublisherError("internal", describeFailure(error));
    return failRedacted(failure.code, failure.message, [config.fundingSeed], "respond failed", failure.stage, failure.detail);
  } finally {
    if (claimed) inFlightRid = undefined;
  }
}
