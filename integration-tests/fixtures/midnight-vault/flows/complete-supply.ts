// Settle side of the supply flow: resolve the MPC's attested outcome by signature
// verification, then settle through the circuit the output selects (completeSupply mints the
// attested stataUSDC shares, refundSupply re-mints the surrendered underlying).
import {
  deserializeEvmOutput,
  MPC_FAILURE_OUTPUT,
  requestIdBytes,
  type RequestIdHex,
  type RespondBidirectionalEvent,
  respondBidirectionalEventToCircuitInput,
  type Secp256k1Point,
  serializeRespondOutput,
  type SignetRequestResponseReader,
  verifyRespondBidirectionalSignature,
} from "@sig-net/midnight";
import { STATA_USDC } from "../contract/src/index.ts";
import { VAULT_SUPPLY_REQUESTS_PATH } from "../contract/src/index.ts";
import { readVaultLedger } from "../contract/src/index.ts";

import { logTokenAmount } from "./evm-logging.ts";
import { SUPPLY_OUTPUT_SCHEMA, SUPPLY_RESPOND_SCHEMA } from "./evm-stata.ts";
import { type ObservedExecution, observeExecution } from "./observed-execution.ts";
import { PollProgress } from "./poll-progress.ts";
import { createResponseReader, type VaultContext } from "./vault-context.ts";

/** The resolved attested outcome of a supply (uint64 shares minted, or the failure output). */
export interface SupplyOutcome {
  readonly event: RespondBidirectionalEvent;
  readonly serializedOutput: Uint8Array;
  readonly shares: bigint;
  readonly matchedFailureOutput: boolean;
}

/** One output a posted attestation may commit to, and the shares settling on it yields. */
interface SupplyCandidate {
  readonly serializedOutput: Uint8Array;
  readonly shares: bigint;
  readonly isFailureOutput: boolean;
}

// How long one candidate build waits on the trace. Short on purpose: the poll
// loop owns the deadline, so a tick that cannot observe gives up fast and the next retries.
const OBSERVATION_TICK_TIMEOUT_MS = 3_000;

/**
 * Recompute both candidate outputs the protocol allows for a supply (the supply-schema twin of
 * complete-swap.ts's candidate build): the success candidate is the observed traced
 * output decoded per the uint256 output schema and re-packed per the uint64 respond schema, the
 * failure candidate is the protocol's fixed 5-byte output. A decode failure drops the success
 * candidate with a warning. An execution has one fixed observation per request, so a caller
 * resolving this once holds the candidates for its whole poll.
 *
 * @param context - The flow context, whose EVM endpoint serves the trace.
 * @param reader - The reader over the supply request map, which rebuilds the mined transaction.
 * @param requestId - The supply request id whose execution result to recompute.
 * @param progress - Diagnostics for the enclosing poll.
 * @returns The candidates, failure last, or undefined when the execution cannot be observed this tick.
 */
async function fetchSupplyCandidates(
  context: VaultContext,
  reader: SignetRequestResponseReader,
  requestId: RequestIdHex,
  progress: PollProgress,
): Promise<SupplyCandidate[] | undefined> {
  let observed: ObservedExecution;
  try {
    observed = await observeExecution(
      reader,
      context.evmRpcUrl,
      requestId,
      OBSERVATION_TICK_TIMEOUT_MS,
    );
  } catch (error) {
    progress.failure("observation", `execution observation failed: ${String(error)}`);
    return undefined;
  }

  const candidates: SupplyCandidate[] = [];
  if (observed.success && observed.output !== null) {
    try {
      const decoded = deserializeEvmOutput(SUPPLY_OUTPUT_SCHEMA, observed.output);
      candidates.push({
        serializedOutput: serializeRespondOutput(SUPPLY_RESPOND_SCHEMA, decoded),
        shares: (decoded as { shares: bigint }).shares,
        isFailureOutput: false,
      });
    } catch (error) {
      progress.failure("decode", `execution output decode failed: ${String(error)}`);
    }
  }
  candidates.push({ serializedOutput: MPC_FAILURE_OUTPUT, shares: 0n, isFailureOutput: true });
  return candidates;
}

/**
 * Select the outcome of the first posted event whose ECDSA signature verifies over one of
 * `candidates`. The signature-only event carries no digest, so this signature check against the
 * vault-pinned response key is the whole of candidate selection.
 *
 * @param events - The posts declared under `requestId`, unverified as the event log allows.
 * @param requestId - The supply request id the attestation must commit to.
 * @param candidates - The recomputed outputs to try, in preference order.
 * @param mpcResponseKey - The response key the vault pinned at initialise.
 * @returns The matching outcome, or undefined when no post attests any candidate.
 */
function matchSupplyOutcome(
  events: readonly RespondBidirectionalEvent[],
  requestId: RequestIdHex,
  candidates: readonly SupplyCandidate[],
  mpcResponseKey: Secp256k1Point,
): SupplyOutcome | undefined {
  for (const candidate of candidates) {
    const event = events.find((posted) =>
      verifyRespondBidirectionalSignature(
        requestIdBytes(requestId),
        candidate.serializedOutput,
        posted,
        mpcResponseKey,
      ),
    );
    if (event !== undefined) {
      return {
        event,
        serializedOutput: candidate.serializedOutput,
        shares: candidate.shares,
        matchedFailureOutput: candidate.isFailureOutput,
      };
    }
  }
  return undefined;
}

/** Options for {@link pollSupplyOutcome}. */
export interface PollSupplyOutcomeOptions {
  /** The supply request id to resolve. */
  readonly requestId: RequestIdHex;
  /** Poll interval; 1s when omitted. */
  readonly intervalMs?: number;
  /** Give-up horizon; 6 minutes when omitted. */
  readonly timeoutMs?: number;
}

const MINUTE = 60_000;

/**
 * Poll until the MPC posts a signature-verified attestation for the supply
 * (see {@link matchSupplyOutcome} for candidate selection).
 *
 * Everything a tick would otherwise redo is resolved once: the reader, whose request-record
 * cache a rebuild would throw away, the response key the vault pinned at initialise, and the
 * candidates {@link fetchSupplyCandidates} builds from the execution's fixed observation. A tick
 * costs one event read plus a signature check per candidate.
 *
 * @param context - The flow context.
 * @param options - The request id and poll cadence.
 * @returns The resolved outcome (attested shares minted, or the failure output).
 * @throws {Error} If no matching attestation posts within the timeout.
 */
export async function pollSupplyOutcome(
  context: VaultContext,
  options: PollSupplyOutcomeOptions,
): Promise<SupplyOutcome> {
  const reader = createResponseReader(context, VAULT_SUPPLY_REQUESTS_PATH);
  // The key the settle circuit verifies against, read from the vault's own ledger: checking
  // off-chain against anything else risks accepting a post that cannot prove. initialise
  // writes it once and nothing rewrites it, so one read serves every tick.
  const { mpcResponseKey } = await readVaultLedger(
    context.providers.publicDataProvider,
    context.vaultContractAddress,
  );

  const progress = new PollProgress(
    `supply attestation ${options.requestId}`,
    options.timeoutMs ?? 6 * MINUTE,
  );
  const end = Date.now() + (options.timeoutMs ?? 6 * MINUTE);
  let candidates: SupplyCandidate[] | undefined;
  while (Date.now() < end) {
    const events = await reader.getRespondBidirectionalEvents(options.requestId);
    progress.update(`${String(events.length)} attestation posts observed`);
    // A posted attestation means the transaction has executed and its result is observable, so
    // the candidates are worth building only once a post appears.
    if (events.length > 0) {
      candidates ??= await fetchSupplyCandidates(context, reader, options.requestId, progress);
      if (candidates !== undefined) {
        const outcome = matchSupplyOutcome(events, options.requestId, candidates, mpcResponseKey);
        if (outcome !== undefined) return outcome;
        progress.update(
          `${String(events.length)} attestation posts rejected against ${String(candidates.length)} output candidates`,
        );
        progress.failure(
          "verification",
          "no signature verifies against the vault response key and observed output",
        );
      }
    }
    await new Promise((r) => setTimeout(r, options.intervalMs ?? 1000));
  }
  throw new Error(`timed out: ${progress.summary()}`);
}

/**
 * Settle a resolved supply outcome through the circuit its content selects:
 * `completeSupply` for attested shares (mints the stataUSDC), `refundSupply`
 * for the fixed MPC failure output (re-mints the surrendered underlying).
 *
 * @param context - The flow context.
 * @param requestId - The supply request id being settled.
 * @param outcome - The attested outcome from {@link pollSupplyOutcome}.
 * @returns The attested shares minted (0 on refund) and whether the supply was refunded.
 */
export async function settleSupply(
  context: VaultContext,
  requestId: RequestIdHex,
  outcome: SupplyOutcome,
): Promise<{ shares: bigint; refunded: boolean }> {
  const mintNonce = crypto.getRandomValues(new Uint8Array(32));
  if (outcome.matchedFailureOutput) {
    console.log("supply tx never executed: refunding the underlying to this wallet");
    const r = await context.vault.callTx.refundSupply(
      requestIdBytes(requestId),
      respondBidirectionalEventToCircuitInput(outcome.event),
      outcome.serializedOutput,
      mintNonce,
    );
    console.log(`refund settled in tx ${r.public.txId}`);
    return { shares: 0n, refunded: true };
  }
  const r = await context.vault.callTx.completeSupply(
    requestIdBytes(requestId),
    respondBidirectionalEventToCircuitInput(outcome.event),
    outcome.serializedOutput,
    mintNonce,
  );
  console.log(`completeSupply settled in tx ${r.public.txId}`);
  await logTokenAmount(
    context.evmRpcUrl,
    STATA_USDC,
    context.evmVaultAddress,
    outcome.shares,
    "minted shares",
  );
  return { shares: outcome.shares, refunded: false };
}

/**
 * Poll until the supply outcome resolves, then settle: {@link pollSupplyOutcome}
 * followed by {@link settleSupply}.
 *
 * @param context - The flow context.
 * @param requestId - The supply request id to settle.
 * @returns The attested shares minted (0 on refund) and whether the supply was refunded.
 */
export async function completeSupply(
  context: VaultContext,
  requestId: RequestIdHex,
): Promise<{ shares: bigint; refunded: boolean }> {
  const outcome = await pollSupplyOutcome(context, { requestId });
  return settleSupply(context, requestId, outcome);
}
