import {
  createUnprovenCallTx,
  type CallTxOptionsWithPrivateStateId,
} from "@midnight-ntwrk/midnight-js/contracts";
import {
  FailFallible,
  SucceedEntirely,
  type FinalizedTxData,
} from "@midnight-ntwrk/midnight-js/types";
import type { UnprovenTransaction } from "@midnightntwrk/ledger-v9";
import { bytesToHex, hexToBytes } from "@sig-net/midnight";
import { ledger, type ProvableCircuits } from "./managed/caller/contract/index.js";
import { applicationOrder, placementOf, type CallPlacement } from "./placement.js";
import {
  CALLER_PRIVATE_STATE_ID,
  callerCompiledContract,
  type CallerCircuitId,
  type CallerContract,
  type CallerProviders,
} from "./providers.js";
import type { CallerPrivateState } from "./witnesses.js";

/** The circuits' shared request shape. */
export interface IsEvenCall {
  evmNonce: bigint;
  to: Uint8Array;
  argWord: Uint8Array;
}

/**
 * Transaction shapes that place singleton notifications in guaranteed and fallible
 * transcripts. Calls from the same transaction touch the same two contracts, so the
 * ledger's causality check requires a guaranteed intent to precede every fallible one.
 */
export enum PlacementScenario {
  /** One call whose whole transcript, singleton call included, is fallible. */
  FallibleOnly = "fallibleOnly",
  /** One guaranteed call that notifies twice. */
  GuaranteedTranscriptPair = "guaranteedTranscriptPair",
  /** One fallible call that notifies twice. */
  FallibleTranscriptPair = "fallibleTranscriptPair",
  /** A guaranteed intent followed by a fallible intent. */
  GuaranteedThenFallibleSegments = "guaranteedThenFallibleSegments",
  /** Two fallible intents, the second call's in the lower segment. */
  FallibleSegmentPair = "fallibleSegmentPair",
  /** A guaranteed intent followed by a fallible intent that fails when applied. */
  PartialSuccess = "partialSuccess",
}

export interface PlacementOutcome {
  status: typeof SucceedEntirely | typeof FailFallible;
  /** Request ids in the order of the scenario's calls. */
  requests: string[];
  /** Notifications in the order the ledger applies them. */
  notifications: string[];
  /** Requests present in the caller's ledger after the transaction. */
  committed: string[];
  placement: CallPlacement[];
}

export interface PlacementContext {
  providers: CallerProviders;
  callerAddress: string;
  signetAddress: string;
  schema: Uint8Array;
  /** Submits a bumpGate call transaction. */
  bumpGate: () => Promise<unknown>;
}

type CircuitArgs<K extends CallerCircuitId> =
  Parameters<ProvableCircuits<CallerPrivateState>[K]> extends [unknown, ...infer Args]
    ? Args
    : never;

interface BuiltCall {
  tx: UnprovenTransaction;
  segment: number;
  requests: string[];
}

const normalizeAddress = (address: string) => address.replace(/^0x/i, "").toLowerCase();

async function buildCall<K extends CallerCircuitId>(
  context: PlacementContext,
  circuitId: K,
  args: CircuitArgs<K>,
): Promise<BuiltCall> {
  // `args` is typed from the generated circuit; the options type's conditional argument
  // member cannot be resolved for a generic circuit id.
  const options = {
    compiledContract: callerCompiledContract,
    contractAddress: context.callerAddress,
    circuitId,
    privateStateId: CALLER_PRIVATE_STATE_ID,
    args,
  } as unknown as CallTxOptionsWithPrivateStateId<CallerContract, K>;
  const built = await createUnprovenCallTx(context.providers, options);
  const segments = [...(built.private.unprovenTx.intents?.keys() ?? [])];
  const [segment] = segments;
  if (segments.length !== 1 || segment === undefined) {
    throw new Error(`${circuitId} built ${segments.length} intents, expected one`);
  }
  const result: unknown = built.private.result;
  const requests = Array.isArray(result) ? result : [result];
  return {
    tx: built.private.unprovenTx,
    segment,
    requests: requests.map((requestId) => bytesToHex(requestId as Uint8Array)),
  };
}

// midnight-js randomizes each intent's segment; rebuild both calls until the first lands in
// the lower segment.
async function buildOrdered(
  buildLower: () => Promise<BuiltCall>,
  buildHigher: () => Promise<BuiltCall>,
): Promise<[BuiltCall, BuiltCall]> {
  for (let attempt = 0; attempt < 32; attempt += 1) {
    const lower = await buildLower();
    const higher = await buildHigher();
    if (lower.segment < higher.segment) return [lower, higher];
  }
  throw new Error("could not order the two intents' segments");
}

function expectPhases(
  placement: readonly CallPlacement[],
  phases: ReadonlyMap<number, "guaranteed" | "fallible">,
): void {
  for (const [segment, phase] of phases) {
    const calls = placement.filter((call) => call.segment === segment);
    const wholly = (call: CallPlacement) =>
      phase === "guaranteed"
        ? call.guaranteed && !call.fallible
        : call.fallible && !call.guaranteed;
    if (calls.length === 0 || !calls.every(wholly)) {
      throw new Error(`segment ${segment} is not wholly ${phase}: ${JSON.stringify(calls)}`);
    }
  }
}

async function committedRequests(context: PlacementContext, requests: string[]): Promise<string[]> {
  const state = await context.providers.publicDataProvider.queryContractState(
    context.callerAddress,
  );
  if (!state) throw new Error(`no caller state found at ${context.callerAddress}`);
  const map = ledger(state.data).requests;
  return requests.filter((requestId) => map.member(hexToBytes(requestId)));
}

async function currentGate(context: PlacementContext): Promise<bigint> {
  const state = await context.providers.publicDataProvider.queryContractState(
    context.callerAddress,
  );
  if (!state) throw new Error(`no caller state found at ${context.callerAddress}`);
  return ledger(state.data).gate;
}

async function submitBuilt(
  context: PlacementContext,
  tx: UnprovenTransaction,
  beforeBalancing: () => Promise<unknown>,
): Promise<FinalizedTxData> {
  const proven = await context.providers.proofProvider.proveTx(tx);
  await beforeBalancing();
  const balanced = await context.providers.walletProvider.balanceTx(proven);
  const txId = await context.providers.midnightProvider.submitTx(balanced);
  return context.providers.publicDataProvider.watchForTxData(txId);
}

/**
 * Builds, checks and submits one placement scenario.
 *
 * @throws When the built transaction's placement or the ledger outcome differs from the
 *   scenario, so a changed partitioner cannot silently weaken the test.
 */
export async function submitPlacement(
  context: PlacementContext,
  scenario: PlacementScenario,
  calls: readonly IsEvenCall[],
): Promise<PlacementOutcome> {
  const [first, second] = calls;
  if (first === undefined) throw new Error(`${scenario} needs a call`);
  const placed = (call: IsEvenCall, fallible: boolean) =>
    buildCall(context, "submitPlacedRequest", [call, context.schema, fallible]);

  let parts: BuiltCall[];
  let phases: Map<number, "guaranteed" | "fallible">;
  let beforeBalancing = () => Promise.resolve();
  if (scenario === PlacementScenario.FallibleOnly) {
    const call = await placed(first, true);
    parts = [call];
    phases = new Map([[call.segment, "fallible"]]);
  } else if (second === undefined) {
    throw new Error(`${scenario} needs two calls`);
  } else if (
    scenario === PlacementScenario.GuaranteedTranscriptPair ||
    scenario === PlacementScenario.FallibleTranscriptPair
  ) {
    const fallible = scenario === PlacementScenario.FallibleTranscriptPair;
    const call = await buildCall(context, "submitPlacedRequestPair", [
      first,
      second,
      context.schema,
      fallible,
    ]);
    parts = [call];
    phases = new Map([[call.segment, fallible ? "fallible" : "guaranteed"]]);
  } else if (scenario === PlacementScenario.FallibleSegmentPair) {
    const [lower, higher] = await buildOrdered(
      () => placed(second, true),
      () => placed(first, true),
    );
    parts = [higher, lower];
    phases = new Map([
      [lower.segment, "fallible"],
      [higher.segment, "fallible"],
    ]);
  } else {
    let buildHigher = () => placed(second, true);
    if (scenario === PlacementScenario.PartialSuccess) {
      const gate = await currentGate(context);
      buildHigher = () => buildCall(context, "submitGatedRequest", [second, context.schema, gate]);
      beforeBalancing = async () => {
        await context.bumpGate();
      };
    }
    const [lower, higher] = await buildOrdered(() => placed(first, false), buildHigher);
    parts = [lower, higher];
    phases = new Map([
      [lower.segment, "guaranteed"],
      [higher.segment, "fallible"],
    ]);
  }

  const [head, ...rest] = parts;
  if (head === undefined) throw new Error(`${scenario} built no calls`);
  const tx = rest.reduce((merged, part) => merged.merge(part.tx), head.tx);
  const placement = placementOf(tx);
  expectPhases(placement, phases);
  const requests = parts.flatMap((part) => part.requests);
  const signet = normalizeAddress(context.signetAddress);
  const notifications = applicationOrder(
    placement.filter((call) => normalizeAddress(call.address) === signet),
  );
  if ([...notifications].sort().join() !== [...requests].sort().join()) {
    throw new Error(
      `${scenario} notified [${notifications.join()}] but filed [${requests.join()}]`,
    );
  }

  const finalized = await submitBuilt(context, tx, beforeBalancing);
  const status = scenario === PlacementScenario.PartialSuccess ? FailFallible : SucceedEntirely;
  if (finalized.status !== status) {
    throw new Error(`${scenario} finalized as ${finalized.status}, expected ${status}`);
  }
  return {
    status,
    requests,
    notifications,
    committed: await committedRequests(context, requests),
    placement,
  };
}
