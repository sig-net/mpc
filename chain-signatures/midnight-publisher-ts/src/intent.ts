// Runs a Compact circuit to obtain its Impact transcript, the one step that cannot move
// to Rust: compactc emits TypeScript and nothing else. Pure: every input arrives from the caller.

import { Effect, Layer } from "effect";
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
  Contract as SignetContract,
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

export const RESPOND_CIRCUITS = ["respond", "respondBidirectional"] as const satisfies readonly SignetContractCircuitId[];

export type RespondCircuit = (typeof RESPOND_CIRCUITS)[number];

type CompiledSignetContract = SignetContract<SignetContractPrivateState>;
// Compact's branded id widens to every generated circuit, so check each argument
// tuple against its generated function before passing it to the executor.
type CircuitArguments<K extends RespondCircuit> = Parameters<CompiledSignetContract["provableCircuits"][K]> extends [
  unknown,
  ...infer Arguments,
]
  ? Arguments
  : never;

const RESPOND_CIRCUIT_ID = ProvableCircuitId<CompiledSignetContract>("respond");
const RESPOND_BIDIRECTIONAL_CIRCUIT_ID =
  ProvableCircuitId<CompiledSignetContract>("respondBidirectional");

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

// `Configuration.Keys` is required even though respond signs nothing: the one executable
// also serves the maintenance operations, and it reads `keys.coinPublic` off the provider.
function executionContext(coinPublicKey: string) {
  return Layer.mergeAll(
    ZKFileConfiguration.layer(signetContractManagedPath).pipe(Layer.provide(NodeContext.layer)),
    Layer.provide(
      Configuration.layer,
      Layer.setConfigProvider(Configuration.configProvider({ keys: { coinPublic: coinPublicKey } })),
    ),
  );
}

/**
 * NOT byte-deterministic: the communication commitment is sampled per call. Assert on
 * the decoded call, never the bytes.
 */
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
  // Both publisher entry points are provable, so a same-named proofless operation
  // cannot be the implementation this process was compiled to call.
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
  const requestId = fromHex(input.requestId);
  const event = { signature: signatureStruct(input.signature) };
  const layer = executionContext(input.coinPublicKey);
  const result =
    input.circuit === "respond"
      ? await Effect.runPromise(
          executable
            .circuit(
              RESPOND_CIRCUIT_ID,
              context,
              ...([requestId, event] satisfies CircuitArguments<"respond">),
            )
            .pipe(Effect.provide(layer)),
        )
      : await Effect.runPromise(
          executable
            .circuit(
              RESPOND_BIDIRECTIONAL_CIRCUIT_ID,
              context,
              ...([requestId, event] satisfies CircuitArguments<"respondBidirectional">),
            )
            .pipe(Effect.provide(layer)),
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

  return Intent.new(new Date(input.ttlSeconds * 1000)).addCall(prototype).serialize();
}
