import type { ProofProvider } from "@midnight-ntwrk/midnight-js/types";
import type { AlignedValue, Op, Transcript, UnprovenTransaction } from "@midnightntwrk/ledger-v9";
import {
  bytesToHex,
  decodeSignBidirectionalEventNotificationPayload,
  decodeSignetEventName,
  SIGNET_EVENT_NAME_LENGTH,
  SIGNET_EVENT_PAYLOAD_LENGTH,
  SignetEventName,
} from "@sig-net/midnight";

/** Where the ledger will run one contract call of a built transaction. */
export interface CallPlacement {
  /** The intent's physical segment. */
  segment: number;
  /** The call's position among the intent's actions. */
  action: number;
  address: string;
  entryPoint: string;
  guaranteed: boolean;
  fallible: boolean;
  /** Request ids of the SignBidirectionalEvent logs each transcript emits, in program order. */
  guaranteedNotifications: string[];
  fallibleNotifications: string[];
}

// A logged item is the array (version, type, data); the data cell is one byte atom holding
// the event name followed by its payload, with trailing zeros trimmed.
function notifiedRequestId(pushed: Op<AlignedValue> | undefined): string | undefined {
  if (pushed === undefined || typeof pushed !== "object" || !("push" in pushed)) {
    throw new Error("a log instruction does not follow a push");
  }
  const item = pushed.push.value;
  const data = item.tag === "array" ? item.content[2] : undefined;
  const atom = data?.tag === "cell" ? data.content.value[0] : undefined;
  if (atom === undefined) throw new Error("a logged item has no data cell");
  const bytes = new Uint8Array(SIGNET_EVENT_NAME_LENGTH + SIGNET_EVENT_PAYLOAD_LENGTH);
  bytes.set(atom);
  const name = decodeSignetEventName(bytes.slice(0, SIGNET_EVENT_NAME_LENGTH));
  if (name !== String(SignetEventName.SignBidirectionalEvent)) return undefined;
  return bytesToHex(
    decodeSignBidirectionalEventNotificationPayload(bytes.slice(SIGNET_EVENT_NAME_LENGTH))
      .requestId,
  );
}

function notificationsIn(transcript: Transcript<AlignedValue> | undefined): string[] {
  const program = transcript?.program ?? [];
  return program.flatMap((op, index) => {
    if (op !== "log") return [];
    const requestId = notifiedRequestId(program[index - 1]);
    return requestId === undefined ? [] : [requestId];
  });
}

/** The calls of every intent, ordered by segment and then by action. */
export function placementOf(tx: UnprovenTransaction): CallPlacement[] {
  const placements: CallPlacement[] = [];
  const intents = tx.intents;
  if (intents === undefined) return placements;
  for (const segment of [...intents.keys()].sort((a, b) => a - b)) {
    intents.get(segment)?.actions.forEach((action, index) => {
      if (!("guaranteedTranscript" in action)) return;
      placements.push({
        segment,
        action: index,
        address: String(action.address),
        entryPoint:
          typeof action.entryPoint === "string"
            ? action.entryPoint
            : new TextDecoder().decode(action.entryPoint),
        guaranteed: action.guaranteedTranscript !== undefined,
        fallible: action.fallibleTranscript !== undefined,
        guaranteedNotifications: notificationsIn(action.guaranteedTranscript),
        fallibleNotifications: notificationsIn(action.fallibleTranscript),
      });
    });
  }
  return placements;
}

/**
 * Notifications in ledger application order: every segment's guaranteed transcripts, by
 * segment and then action, before any fallible transcript in the same order.
 */
export function applicationOrder(placement: readonly CallPlacement[]): string[] {
  return [
    ...placement.flatMap((call) => call.guaranteedNotifications),
    ...placement.flatMap((call) => call.fallibleNotifications),
  ];
}

/** Records each transaction's placement before the wrapped provider proves it. */
export function recordingProofProvider(
  inner: ProofProvider,
  record: (placement: CallPlacement[]) => void,
): ProofProvider {
  return {
    proveTx(unprovenTx, config) {
      record(placementOf(unprovenTx));
      return inner.proveTx(unprovenTx, config);
    },
  };
}
