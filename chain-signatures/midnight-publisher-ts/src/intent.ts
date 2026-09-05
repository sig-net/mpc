// Runs a Compact circuit to obtain its Impact transcript, the one step that cannot move
// to Rust: the compiled contract's bindings and executor are JavaScript. Pure: every input
// arrives from the caller.

import { ConfigProvider, Effect, Layer } from "effect";
import { NodeContext } from "@effect/platform-node";
import {
  ContractExecutable,
  encodeContractKeyLocation,
  hashVerifierKey,
  ProvableCircuitId,
} from "@midnight-ntwrk/compact-js";
import { ZKFileConfiguration } from "@midnight-ntwrk/compact-js-node";
// onchain-runtime-v4's ContractState, not ledger-v9's: different WASM classes, and the
// executor refuses the wrong one.
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
  type Contract as SignetContract,
  createSignetContractPrivateState,
  expectedVk,
  type SignetContractCircuitId,
  type SignetContractPrivateState,
} from "@sig-net/midnight-contract";
import {
  signetContractCompiledContract,
  signetContractManagedPath,
} from "@sig-net/midnight-contract-deploy";

import { PublisherError } from "./errors.js";

export const RESPOND_CIRCUITS = [
  "respond",
  "respondBidirectional",
] as const satisfies readonly SignetContractCircuitId[];

export type RespondCircuit = (typeof RESPOND_CIRCUITS)[number];

type CompiledSignetContract = SignetContract<SignetContractPrivateState>;
// Compact's branded id widens to every generated circuit, so check the argument
// tuple against each generated function before passing it to the executor.
type CircuitArguments<K extends RespondCircuit> =
  Parameters<CompiledSignetContract["provableCircuits"][K]> extends [unknown, ...infer Arguments]
    ? Arguments
    : never;

export interface WireSignature {
  readonly bigR: { readonly x: string; readonly y: string };
  readonly s: string;
  readonly recoveryId: 0 | 1;
}

export interface BuildIntentInput {
  readonly circuit: RespondCircuit;
  readonly contractAddress: string;
  readonly requestId: string;
  /** SEC1 big-endian throughout; nothing here re-encodes. */
  readonly signature: WireSignature;
  readonly contractState: string;
  readonly ledgerParameters: string;
  readonly coinPublicKey: string;
  /** Absolute unix seconds; the caller owns the clock. */
  readonly ttlSeconds: number;
}

const fromHex = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, "hex"));

// Big-endian in, big-endian stored: the contract reverses in-circuit.
function signatureStruct(signature: WireSignature) {
  return {
    bigR: { x: fromHex(signature.bigR.x), y: fromHex(signature.bigR.y) },
    s: fromHex(signature.s),
    recoveryId: BigInt(signature.recoveryId),
  };
}

// `Configuration.Keys` is required even though respond signs nothing: the executable reads
// `keys.coinPublic`. Bound from this JSON alone, because platform-js's own provider reads
// the process environment (`NETWORK`, `KEYS_*`) ahead of it.
function executionContext(coinPublicKey: string) {
  return Layer.mergeAll(
    ZKFileConfiguration.layer(signetContractManagedPath).pipe(Layer.provide(NodeContext.layer)),
    Layer.provide(
      Configuration.layer,
      Layer.setConfigProvider(ConfigProvider.fromJson({ keys: { coinPublic: coinPublicKey } })),
    ),
  );
}

/** Not byte-deterministic: the communication commitment is sampled per call. */
export async function buildIntent(input: BuildIntentInput): Promise<Uint8Array> {
  const contractState = ContractState.deserialize(fromHex(input.contractState));

  const operation = contractState.operation(input.circuit);
  if (operation === undefined) {
    throw new PublisherError(
      "contract_mismatch",
      `the contract deployed at ${input.contractAddress} exposes no operation \`${input.circuit}\``,
    );
  }
  const deployedVerifierKey = operation.verifierKey;
  // Both entry points are provable, so a proofless same-named operation cannot be ours.
  if (deployedVerifierKey === undefined || deployedVerifierKey.length === 0) {
    throw new PublisherError(
      "contract_mismatch",
      `the contract deployed at ${input.contractAddress} has no verifier key for \`${input.circuit}\``,
    );
  }
  const verifierKeyHash = hashVerifierKey(deployedVerifierKey);
  if (verifierKeyHash !== expectedVk[input.circuit]) {
    throw new PublisherError(
      "contract_mismatch",
      `the contract deployed at ${input.contractAddress} has a different verifier key for \`${input.circuit}\``,
    );
  }

  const executable = ContractExecutable.make(signetContractCompiledContract);
  const context = {
    address: ContractAddress.ContractAddress(input.contractAddress),
    contractState,
    privateState: createSignetContractPrivateState(),
    ledgerParameters: LedgerParameters.deserialize(fromHex(input.ledgerParameters)),
  };
  // One tuple serves both entry points; the intersection keeps every generated signature
  // checked, so a contract version that diverges them fails here rather than in the executor.
  const args = [
    fromHex(input.requestId),
    { signature: signatureStruct(input.signature) },
  ] satisfies CircuitArguments<"respond"> & CircuitArguments<"respondBidirectional">;
  const result = await Effect.runPromise(
    executable
      .circuit(ProvableCircuitId<CompiledSignetContract>(input.circuit), context, ...args)
      .pipe(Effect.provide(executionContext(input.coinPublicKey))),
  );

  // A second call would mean the contract grew cross-contract calls this builder cannot carry.
  if (result.calls.length !== 1) {
    throw new PublisherError("internal", `expected one contract call, got ${result.calls.length}`);
  }
  const call = result.calls[0]!;

  const prototype = new ContractCallPrototype(
    input.contractAddress,
    input.circuit,
    // Two WASM modules, two `ContractOperation` classes; the serialized form is the bridge.
    LedgerContractOperation.deserialize(operation.serialize()),
    call.public.partitionedTranscript[0],
    call.public.partitionedTranscript[1],
    call.private.privateTranscriptOutputs,
    call.private.input,
    call.private.output,
    communicationCommitmentRandomness(),
    encodeContractKeyLocation({
      contractAddress: input.contractAddress,
      circuitId: input.circuit,
      verifierKeyHash,
    }),
  );

  return Intent.new(new Date(input.ttlSeconds * 1000))
    .addCall(prototype)
    .serialize();
}
