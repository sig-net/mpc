// `POST /respond`: validate, prove, pay, submit.
//
// MECHANISM, NEVER AUTHORITY: the signature was computed by the MPC threshold
// before anything reached this service, both circuits are blind appends, and
// nothing here decides who may write.

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

// One message per field: absent, null, wrong type and wrong value are the same thing here.
const MUST_BE_AN_OBJECT = "must be an object";
const MUST_BE_HEX_32 = "must be 64 lowercase hex";
const MUST_BE_HEX_128 = "must be 256 lowercase hex (Bytes<128>)";
const MUST_BE_A_CIRCUIT = "must be respond or respondBidirectional";
const MUST_BE_AN_OUTPUT_LEN = "must be an integer in 0..=128";

const wireObject = <T extends z.ZodRawShape>(shape: T) => z.object(shape, MUST_BE_AN_OBJECT);

const wireHex = (bytes: number, message: string) =>
  z.string(message).regex(new RegExp(`^[0-9a-f]{${bytes * 2}}$`), message);

const hex32 = wireHex(32, MUST_BE_HEX_32);

// SEC1 BIG-ENDIAN hex, reaching the ledger untouched: this service converts nothing.
const wireSignature = wireObject({
  big_r: wireObject({ x: hex32, y: hex32 }),
  s: hex32,
  recovery_id: z.literal([0, 1], "must be 0|1"),
});

// Field order is wire contract: only the first issue is surfaced and zod reports
// them in declaration order. `circuit` resolves first, being the discriminator.
const RespondRequestSchema = z.discriminatedUnion(
  "circuit",
  [
    wireObject({
      contract_address: hex32,
      circuit: z.literal("respond"),
      request_id: hex32,
      signature: wireSignature,
    }),
    wireObject({
      contract_address: hex32,
      circuit: z.literal("respondBidirectional"),
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

export type RespondRequest = z.infer<typeof RespondRequestSchema>;
export type RespondCircuit = RespondRequest["circuit"];
export type WireSignature = RespondRequest["signature"];

// Deliberately not `jsonObject`'s `invalid JSON:`: past that point the JSON is fine and the request is not.
function toBadRequest(error: z.ZodError): PublisherError {
  const issue = error.issues[0]!;
  const path = issue.path.join(".");
  return new PublisherError("bad_request", `invalid request: ${path.length === 0 ? "" : `\`${path}\` `}${issue.message}`);
}

// What this returns is valid, so nothing downstream re-checks.
export function parseRespondRequest(body: string): RespondRequest {
  const parsed = RespondRequestSchema.safeParse(jsonObject(body));
  if (!parsed.success) throw toBadRequest(parsed.error);
  return parsed.data;
}

type CircuitArgs<K extends RespondCircuit> = readonly [
  requestId: Uint8Array,
  event: Readonly<Parameters<SignetContract<SignetContractPrivateState>["circuits"][K]>[2]>,
];

export type SignatureRespondedEvent = CircuitArgs<"respond">[1];
export type RespondBidirectionalEvent = CircuitArgs<"respondBidirectional">[1];

export type RespondCall = {
  [K in RespondCircuit]: { readonly circuitId: K; readonly args: CircuitArgs<K> };
}[RespondCircuit];

// Big-endian in, big-endian stored: consumers re-encode for circuit args off-chain.
function signatureStruct(signature: WireSignature): SignatureRespondedEvent["signature"] {
  return {
    bigR: { x: fromHex(signature.big_r.x), y: fromHex(signature.big_r.y) },
    s: fromHex(signature.s),
    recoveryId: BigInt(signature.recovery_id),
  };
}

export function respondCall(request: RespondRequest): RespondCall {
  const requestId = fromHex(request.request_id);
  if (request.circuit === "respond") {
    return {
      circuitId: "respond",
      args: [requestId, { signature: signatureStruct(request.signature) }],
    };
  }
  return {
    circuitId: "respondBidirectional",
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

type CallStates = PublicContractStates & { readonly blockHash: BlockHashHex };

// The reads must be fresh at prove time: fees drift per block, so stale parameters are `OutOfGas`.
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

// Every dependency here waits forever by default: a dead indexer never finishes
// wallet sync, `@polkadot/api` queues across reconnects, and `submitTxCore`
// documents that it "waits indefinitely". Unbounded, any of them holds the busy
// gate silently and answers nobody. Blowing it is fatal, see `DeadlineExceeded`.
export const RESPOND_TIMEOUT = { ms: 6 * 60 * 1000 };

// `Promise.race` handles the loser, so the abandoned attempt's own late failure surfaces nowhere.
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

export type Publisher = Readonly<Awaited<ReturnType<typeof buildPublisher>>>;

let publisherPromise: Promise<Publisher> | undefined;

async function buildPublisher(config: Config) {
  // Required before any transaction is built: it decides the network id baked
  // into the transaction and into address encoding.
  setNetworkId(config.networkId);

  const zkConfigProvider = new NodeZkConfigProvider<SignetContractCircuitId>(config.managedDir);
  // The operator's `managedDir`, not the contract package's own asset
  // resolution: anything else bypasses MIDNIGHT_PUB_MANAGED_DIR and guts
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

// Memoized even while PENDING, so a hung indexer costs one wallet facade, not one per retry.
function publisher(config: Config): Promise<Publisher> {
  publisherPromise ??= buildPublisher(config).catch((error: unknown) => {
    publisherPromise = undefined;
    throw error;
  });
  return publisherPromise;
}

export function primePublisher(ready: Promise<Publisher>): void {
  publisherPromise = ready;
}

export async function closePublisher(): Promise<void> {
  const pending = publisherPromise;
  publisherPromise = undefined;
  inFlightRid = undefined;
  if (pending === undefined) return;
  await pending.then((ready) => ready.wallet.close()).catch(() => undefined);
}

// The check the escape-hatch route skips, against the state already read.
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

async function proveCall(ready: Publisher, call: RespondCall, address: string, states: CallStates): Promise<UnboundTransaction> {
  const dependencies = {
    coinPublicKey: ready.wallet.getCoinPublicKey(),
    initialContractState: states.contractState,
    initialZswapChainState: states.zswapChainState,
    ledgerParameters: states.ledgerParameters,
    // The contract declares no witnesses, so this is never consulted: inline it
    // and no private-state provider is needed.
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

type Refinement = readonly [pattern: string, code: ErrorCode];

// Either spelling means back off, not that the request was wrong.
const DUST_SHORTFALL: readonly Refinement[] = [
  ["Wallet.InsufficientFunds", "wallet_unfunded"],
  ["could not balance dust", "wallet_unfunded"],
];

// Best-effort: `submissionService` flattens node errors, so this surfaces only in the cause chain.
const LOST_THE_RACE: readonly Refinement[] = [["ReadMismatch", "state_conflict"]];

// The refinements are the ONLY place this service matches on dependency error text.
async function step<T>(code: ErrorCode, run: () => Promise<T>, refine: readonly Refinement[] = []): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof PublisherError) throw error;
    // The pinned reads are tag-checked before any deserializer runs, so a
    // version mismatch reaching here came out of a dependency's own blob: name
    // that, not the step it happened to surface in.
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

interface Posted {
  readonly txId: string;
  readonly blockHash: string;
}

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

let inFlightRid: string | undefined;

// The one failure that ends the process. Nothing here is cancellable, so a post
// past its deadline keeps the gate AND keeps spending; the alternatives are a
// second post racing it onto the one dust UTXO, or a gate wedged indefinitely.
class DeadlineExceeded extends PublisherError {
  constructor(rid: string) {
    super(
      "internal",
      `respond exceeded the ${RESPOND_TIMEOUT.ms} ms deadline and the publisher is stopping; if it had ` +
        `reached submit the transaction may still land, so check the chain for rid ${rid} before retrying`,
    );
  }
}

// A 200 means finalized: both circuits run wholly in the guaranteed phase.
//
// ONE AT A TIME, NOT QUEUED: the wallet has a single dust UTXO, so a second
// concurrent post could only burn a prove and fail at balance ~35s later.
// Anyone replacing this with a queue must keep the state reads inside it.
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
