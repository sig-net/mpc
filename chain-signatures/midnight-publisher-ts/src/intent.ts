// Runs a Compact circuit to obtain its Impact transcript, the one step that cannot move
// to Rust: compactc emits TypeScript and nothing else. Pure: every input arrives from the caller.

import { Effect, Layer } from "effect";
import { NodeContext } from "@effect/platform-node";
import { ContractExecutable, hashVerifierKey } from "@midnight-ntwrk/compact-js";
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
import { makeVacantCompiledContract } from "@sig-net/midnight-contract-deploy";

import { PublisherError } from "./errors.js";

export type RespondCircuit = Extract<SignetContractCircuitId, "respond" | "respondBidirectional">;

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

function circuitArgs(input: BuildIntentInput): readonly [Uint8Array, unknown] {
  return [fromHex(input.requestId), { signature: signatureStruct(input.signature) }];
}

// `Configuration.Keys` is required even though respond signs nothing: the one executable
// also serves the maintenance operations, and it reads `keys.coinPublic` off the provider.
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
 * NOT byte-deterministic: the communication commitment is sampled per call. Assert on
 * the decoded call, never the bytes.
 */
export async function buildIntent(managedDir: string, input: BuildIntentInput): Promise<Uint8Array> {
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
  if (hashVerifierKey(deployedVerifierKey) !== expectedVk[input.circuit]) {
    throw new PublisherError(
      "contract_mismatch",
      `the contract deployed at ${input.contractAddress} has a different verifier key for \`${input.circuit}\``,
    );
  }

  const compiledContract = makeVacantCompiledContract<
    SignetContract<SignetContractPrivateState>,
    SignetContractPrivateState
  >("signet-contract", SignetContract, managedDir);

  const [requestId, event] = circuitArgs(input);
  // `ProvableCircuitId` does not accept a hand-written union, so the id and argument
  // tuple cross as `never`; the operation lookup above validates the pair.
  const result = await Effect.runPromise(
    ContractExecutable.make(compiledContract)
      .circuit(
        input.circuit as never,
        {
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
    input.circuit,
  );

  return Intent.new(new Date(input.ttlSeconds * 1000)).addCall(prototype).serialize();
}
