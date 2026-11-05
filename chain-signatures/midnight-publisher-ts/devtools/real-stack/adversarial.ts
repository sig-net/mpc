import type { UnprovenTransaction } from "@midnightntwrk/ledger-v9";
import { hexToBytes } from "@sig-net/midnight";
import {
  buildCall,
  buildOrdered,
  currentGate,
  segmentsOf,
  submitBuilt,
  type BuiltCall,
  type IsEvenCall,
  type PlacementContext,
} from "./fallible.js";
import { ledger } from "./managed/caller/contract/index.js";
import { applicationOrder, placementOf, type CallPlacement } from "./placement.js";

/**
 * Partially successful transaction shapes from the partial-success security review. Each
 * names one request; the outcome reports what the ledger committed, not what the MPC did.
 */
export enum AdversarialScenario {
  /**
   * A guaranteed call files a request without notifying; a later fallible call notifies of
   * it and rolls back.
   */
  WriteThenRolledBackNotify = "writeThenRolledBackNotify",
  /**
   * A guaranteed call files and notifies; a fallible call proven before the filing files
   * and notifies the same request, and rolls back after it in the same transaction.
   */
  SameTxReplay = "sameTxReplay",
}

export interface AdversarialOutcome {
  status: string;
  requestId: string;
  /** Whether the caller's ledger holds the request after the transaction. */
  committed: boolean;
  /** Notified request ids in ledger application order. */
  notifications: string[];
  placement: CallPlacement[];
  /** The indexer's per-segment results, `transactionResult.segments`. */
  segments: [number, string][];
  blockHeight: number;
  txHash: string;
}

async function holds(context: PlacementContext, requestId: string): Promise<boolean> {
  const state = await context.providers.publicDataProvider.queryContractState(
    context.callerAddress,
  );
  if (!state) throw new Error(`no caller state found at ${context.callerAddress}`);
  return ledger(state.data).requests.member(hexToBytes(requestId));
}

// reviewShape's request id argument where its mode ignores it.
const NO_REQUEST = new Uint8Array(32);

const normalizeAddress = (address: string) => address.replace(/^0x/i, "").toLowerCase();

async function submitMerged(
  context: PlacementContext,
  parts: readonly BuiltCall[],
  requestId: string,
  beforeBalancing: () => Promise<unknown>,
): Promise<AdversarialOutcome> {
  const segments = parts.map((part) => part.segment);
  if (new Set(segments).size !== segments.length) {
    throw new Error(`intent segments collide: ${segments.join()}`);
  }
  const [head, ...rest] = parts;
  if (head === undefined) throw new Error("no calls to merge");
  const tx: UnprovenTransaction = rest.reduce((merged, part) => merged.merge(part.tx), head.tx);
  const placement = placementOf(tx);
  const signet = normalizeAddress(context.signetAddress);
  const finalized = await submitBuilt(context, tx, beforeBalancing);
  return {
    status: String(finalized.status),
    requestId,
    committed: await holds(context, requestId),
    notifications: applicationOrder(
      placement.filter((call) => normalizeAddress(call.address) === signet),
    ),
    placement,
    segments: segmentsOf(finalized),
    blockHeight: finalized.blockHeight,
    txHash: String(finalized.txHash),
  };
}

export async function submitAdversarial(
  context: PlacementContext,
  scenario: AdversarialScenario,
  call: IsEvenCall,
): Promise<AdversarialOutcome> {
  if (scenario === AdversarialScenario.WriteThenRolledBackNotify) {
    const gate = await currentGate(context);
    const [file, notify] = await buildOrdered(
      () => buildCall(context, "reviewShape", [0n, call, context.schema, NO_REQUEST, 0n]),
      async () => {
        const [requestId] = (
          await buildCall(context, "reviewShape", [0n, call, context.schema, NO_REQUEST, 0n])
        ).requests;
        if (requestId === undefined) throw new Error("reviewShape returned no request id");
        return buildCall(context, "reviewShape", [
          1n,
          call,
          context.schema,
          hexToBytes(requestId),
          gate,
        ]);
      },
    );
    const [requestId] = file.requests;
    if (requestId === undefined) throw new Error("reviewShape returned no request id");
    return submitMerged(context, [file, notify], requestId, () => context.bumpGate());
  }
  const [filing, replay] = await buildOrdered(
    () => buildCall(context, "submitPlacedRequest", [call, context.schema, false]),
    () => buildCall(context, "submitPlacedRequest", [call, context.schema, true]),
  );
  const [requestId] = filing.requests;
  if (requestId === undefined) throw new Error("submitPlacedRequest returned no request id");
  return submitMerged(context, [filing, replay], requestId, () => Promise.resolve());
}

/** Files and notifies `call`'s request in a guaranteed transcript: the twin's original. */
export async function prepareTwin(
  context: PlacementContext,
  call: IsEvenCall,
): Promise<{ requestId: string; blockHeight: number; placement: CallPlacement[] }> {
  const original = await buildCall(context, "submitPlacedRequest", [call, context.schema, false]);
  const [requestId] = original.requests;
  if (requestId === undefined) throw new Error("the original returned no request id");
  const landed = await submitBuilt(context, original.tx, () => Promise.resolve());
  if (String(landed.status) !== "SucceedEntirely") {
    throw new Error(`the original finalized as ${String(landed.status)}`);
  }
  return { requestId, blockHeight: landed.blockHeight, placement: placementOf(original.tx) };
}

/**
 * One transaction: a fallible call that removes the original and files its identical twin
 * (the same request id) and notifies, and a fallible call that fails when applied, so the
 * transaction partially succeeds. The twin's record is in the caller's state before and
 * after the block.
 */
export async function fireTwin(
  context: PlacementContext,
  requestId: string,
  call: IsEvenCall,
  failingCall: IsEvenCall,
): Promise<AdversarialOutcome> {
  const refile = await buildCall(context, "reviewShape", [
    2n,
    call,
    context.schema,
    hexToBytes(requestId),
    0n,
  ]);
  if (refile.requests[0] !== requestId) throw new Error("the twin names another request");
  const gate = await currentGate(context);
  let failing: BuiltCall | undefined;
  for (let attempt = 0; attempt < 32 && failing === undefined; attempt += 1) {
    const built = await buildCall(context, "submitGatedRequest", [
      failingCall,
      context.schema,
      gate,
    ]);
    if (built.segment !== refile.segment) failing = built;
  }
  if (failing === undefined) throw new Error("could not place the failing call");
  return submitMerged(context, [refile, failing], requestId, () => context.bumpGate());
}
