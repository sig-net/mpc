// The one step that cannot move to Rust: running a Compact circuit to obtain its
// Impact transcript. compactc emits TypeScript and nothing else, so this file
// exists for exactly as long as that is true. Everything downstream of the Intent
// it returns (balance, prove, sign, submit) is Rust's.
//
// Pure: no network, no chain reads, no wallet, no seed. Every input arrives from
// the caller, which is what lets the caller keep the funding key.

import { Effect, Layer } from "effect";
import { NodeContext } from "@effect/platform-node";
import { ContractExecutable } from "@midnight-ntwrk/compact-js";
import { ZKFileConfiguration } from "@midnight-ntwrk/compact-js-node";
// The executor wants onchain-runtime-v4's ContractState, NOT ledger-v9's. They are
// different WASM classes and the runtime refuses the wrong one, in `coerceToChargedState`,
// with "has unexpected type".
import { ContractState } from "@midnight-ntwrk/compact-runtime";
import * as ContractAddress from "@midnight-ntwrk/platform-js/effect/ContractAddress";
import * as Configuration from "@midnight-ntwrk/platform-js/effect/Configuration";
import {
  ContractCallPrototype,
  ContractOperation as LedgerContractOperation,
  Intent,
  LedgerParameters,
  communicationCommitmentRandomness,
} from "@midnightntwrk/ledger-v9";
import {
  Contract as SignetContract,
  createSignetContractPrivateState,
  type SignetContractCircuitId,
  type SignetContractPrivateState,
} from "@sig-net/midnight-contract";
import { makeVacantCompiledContract } from "@sig-net/midnight-contract-deploy";

import { PublisherError } from "./errors.js";

// Narrowed from the contract's own circuit ids rather than spelled fresh, so a
// renamed circuit is a type error here instead of a runtime entry-point miss.
export type RespondCircuit = Extract<SignetContractCircuitId, "respond" | "respondBidirectional">;

export interface WireSignature {
  readonly bigR: { readonly x: string; readonly y: string };
  readonly s: string;
  readonly recoveryId: 0 | 1;
}

export interface BuildIntentInput {
  readonly circuit: RespondCircuit;
  /** 64 lowercase hex, no `0x`. */
  readonly contractAddress: string;
  /** 64 lowercase hex. */
  readonly requestId: string;
  /** SEC1 BIG-ENDIAN throughout; nothing here re-encodes. */
  readonly signature: WireSignature;
  /** `respondBidirectional` only: exactly 256 lowercase hex, a whole `Bytes<128>`. */
  readonly serializedOutput?: string;
  /** `respondBidirectional` only: 0..=128. */
  readonly outputLen?: number;
  /** Hex of the ledger-serialized onchain-runtime-v4 `ContractState`. */
  readonly contractState: string;
  /** Hex of the ledger-serialized ledger-v9 `LedgerParameters`. */
  readonly ledgerParameters: string;
  /** The funding wallet's Zswap public key, 64 lowercase hex. Public, never the seed. */
  readonly coinPublicKey: string;
  /** Absolute unix seconds. The caller owns the clock so this stays a pure function. */
  readonly ttlSeconds: number;
}

const fromHex = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, "hex"));

// Big-endian in, big-endian stored: the contract reverses in-circuit, so nothing converts here.
function signatureStruct(signature: WireSignature) {
  return {
    bigR: { x: fromHex(signature.bigR.x), y: fromHex(signature.bigR.y) },
    s: fromHex(signature.s),
    recoveryId: BigInt(signature.recoveryId),
  };
}

function circuitArgs(input: BuildIntentInput): readonly [Uint8Array, unknown] {
  const requestId = fromHex(input.requestId);
  if (input.circuit === "respond") {
    return [requestId, { signature: signatureStruct(input.signature) }];
  }
  if (input.serializedOutput === undefined || input.outputLen === undefined) {
    throw new PublisherError("bad_request", "respondBidirectional needs serializedOutput and outputLen");
  }
  return [
    requestId,
    {
      serializedOutput: fromHex(input.serializedOutput),
      outputLen: BigInt(input.outputLen),
      signature: signatureStruct(input.signature),
    },
  ];
}

// `ContractExecutable.circuit` requires `ZKConfiguration | Configuration.Keys`.
// `ZKFileConfiguration.layer` is the official reader for a managed dir and needs
// `Path | FileSystem`, which `NodeContext.layer` supplies. `Configuration.Keys` is
// required even though respond signs nothing, because one executable also serves
// the maintenance operations; it reads `keys.coinPublic` out of the config provider.
function executionContext(managedDir: string, coinPublicKey: string) {
  return Layer.mergeAll(
    ZKFileConfiguration.layer(managedDir).pipe(Layer.provide(NodeContext.layer)),
    Layer.provide(
      Configuration.layer,
      Layer.setConfigProvider(Configuration.configProvider({ keys: { coinPublic: coinPublicKey } })),
    ),
  );
}

/**
 * Runs the respond circuit and returns the bytes of a serialized ledger `Intent`
 * carrying exactly one contract call.
 *
 * NOT byte-deterministic: `communicationCommitmentRandomness` is sampled per call.
 * The commitment is what unlinks a call from its caller, so a fixed value would be
 * a privacy regression, not a convenience. Assert on the decoded call, never on the
 * bytes.
 */
export async function buildIntent(managedDir: string, input: BuildIntentInput): Promise<Uint8Array> {
  const contractState = ContractState.deserialize(fromHex(input.contractState));

  // The deployed operation, read off the state the caller handed us. An absent entry
  // point is how a managed-dir/chain mismatch surfaces. By NAME only: this is weaker
  // than comparing verifier keys, which catches a managed dir whose circuit names still
  // match but whose keys have moved on. That comparison belongs to whoever balances and
  // proves, which is no longer this process.
  const operation = contractState.operation(input.circuit);
  if (operation === undefined) {
    throw new PublisherError(
      "contract_mismatch",
      `the contract deployed at ${input.contractAddress} exposes no operation \`${input.circuit}\``,
    );
  }

  const compiledContract = makeVacantCompiledContract<
    SignetContract<SignetContractPrivateState>,
    SignetContractPrivateState
  >("signet-contract", SignetContract, managedDir);

  const [requestId, event] = circuitArgs(input);
  // `ProvableCircuitId` is derived from the compiled contract's own circuit table and
  // does not accept a hand-written union, so the id and the argument tuple both cross
  // as `never`. What actually validates the pair is `contractState.operation()` above
  // plus the per-circuit tests; the compiler cannot check a runtime-chosen circuit.
  const result = await Effect.runPromise(
    ContractExecutable.make(compiledContract)
      .circuit(
        input.circuit as never,
        {
          // Branded, and the brand constructor validates the hex: a malformed address
          // fails here by name rather than inside WASM as "Odd number of digits".
          address: ContractAddress.ContractAddress(input.contractAddress),
          contractState,
          privateState: createSignetContractPrivateState(),
          ledgerParameters: LedgerParameters.deserialize(fromHex(input.ledgerParameters)),
        },
        requestId,
        event as never,
      )
      .pipe(Effect.provide(executionContext(managedDir, input.coinPublicKey))),
  );

  // Both respond circuits are blind appends that call no one, so the root call is the
  // only call. Assert it rather than indexing blindly: a second call would mean the
  // contract grew a cross-contract call and this builder needs to carry commitments.
  if (result.calls.length !== 1) {
    throw new PublisherError("internal", `expected one contract call, got ${result.calls.length}`);
  }
  const call = result.calls[0]!;

  const prototype = new ContractCallPrototype(
    input.contractAddress,
    input.circuit,
    // Two WASM modules, two `ContractOperation` classes. The serialized form is the
    // only thing they share, so it is the bridge.
    LedgerContractOperation.deserialize(operation.serialize()),
    call.public.partitionedTranscript[0],
    call.public.partitionedTranscript[1],
    call.private.privateTranscriptOutputs,
    call.private.input,
    call.private.output,
    communicationCommitmentRandomness(),
    input.circuit,
  );

  return Intent.new(new Date(input.ttlSeconds * 1000)).addCall(prototype).serialize();
}
