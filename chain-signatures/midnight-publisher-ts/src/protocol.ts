// One JSON object per line each way, `id` echoed, absent `op` meaning `build`. The Rust
// client mirrors these shapes exactly: renaming or retyping a field breaks both sides at once.

import { z } from "zod";

import { type Config } from "./config.js";
import { describeFailure, jsonObject, PublisherError, type ErrorCode } from "./errors.js";
import { buildIntent, type BuildIntentInput } from "./intent.js";
import { handleSubmit } from "./submit.js";

export type BuildRequest = { readonly id: number } & BuildIntentInput;

export type SubmitRequest = { readonly id: number; readonly intent: string };

export type Response =
  | { readonly id: number; readonly ok: true; readonly intent: string }
  | { readonly id: number; readonly ok: true; readonly txId: string }
  | { readonly id: number | null; readonly ok: false; readonly code: ErrorCode; readonly message: string };

const MUST_BE_AN_OBJECT = "must be an object";
const MUST_BE_AN_ID = "must be an integer in 0..=2^53-1";
const MUST_BE_HEX_32 = "must be 64 lowercase hex";
const MUST_BE_LEDGER_HEX = "must be lowercase hex, an even number of digits";
const MUST_BE_A_CIRCUIT = "must be respond or respondBidirectional";
const MUST_BE_A_TTL = "must be a positive integer, in absolute unix seconds";
const MUST_BE_AN_OP = "must be build or submit";

const wireObject = <T extends z.ZodRawShape>(shape: T) => z.object(shape, MUST_BE_AN_OBJECT);

const wireHex = (bytes: number, message: string) =>
  z.string(message).regex(new RegExp(`^[0-9a-f]{${bytes * 2}}$`), message);

const hex32 = wireHex(32, MUST_BE_HEX_32);

const ledgerHex = z.string(MUST_BE_LEDGER_HEX).regex(/^(?:[0-9a-f]{2})+$/, MUST_BE_LEDGER_HEX);

const wireSignature = wireObject({
  bigR: wireObject({ x: hex32, y: hex32 }),
  s: hex32,
  recoveryId: z.literal([0, 1], "must be 0|1"),
});

// `JSON.parse` silently rounds past 2^53, so the Rust side must keep its ids inside the range.
const wireId = z
  .int(MUST_BE_AN_ID)
  .nonnegative(MUST_BE_AN_ID)
  .max(Number.MAX_SAFE_INTEGER, MUST_BE_AN_ID);

const SubmitSchema = wireObject({ id: wireId, intent: ledgerHex });

const BuildSchema = wireObject({
  id: wireId,
  contractAddress: hex32,
  circuit: z.literal(["respond", "respondBidirectional"], MUST_BE_A_CIRCUIT),
  requestId: hex32,
  signature: wireSignature,
  contractState: ledgerHex,
  ledgerParameters: ledgerHex,
  coinPublicKey: hex32,
  ttlSeconds: z.int(MUST_BE_A_TTL).positive(MUST_BE_A_TTL),
});

function toBadRequest(error: z.ZodError): PublisherError {
  const issue = error.issues[0]!;
  const path = issue.path.join(".");
  return new PublisherError("bad_request", `invalid request: ${path.length === 0 ? "" : `\`${path}\` `}${issue.message}`);
}

function readId(body: Record<string, unknown>): number | null {
  const id = body["id"];
  return typeof id === "number" && Number.isSafeInteger(id) && id >= 0 ? id : null;
}

// Absent `op` is `build`: the request predates the discriminator and the Rust client
// sends none. An unknown op hits `default` before either schema can blame a missing field.
async function answer(config: Config, body: Record<string, unknown>): Promise<Response> {
  switch (body["op"]) {
    case undefined:
    case "build": {
      const parsed = BuildSchema.safeParse(body);
      if (!parsed.success) throw toBadRequest(parsed.error);
      const request: BuildRequest = parsed.data;
      const intent = await buildIntent(config.managedDir, request);
      return { id: request.id, ok: true, intent: Buffer.from(intent).toString("hex") };
    }
    case "submit": {
      const parsed = SubmitSchema.safeParse(body);
      if (!parsed.success) throw toBadRequest(parsed.error);
      const request: SubmitRequest = parsed.data;
      const landed = await handleSubmit(config, request.id, Buffer.from(request.intent, "hex"));
      return { id: request.id, ok: true, txId: landed.txId };
    }
    default:
      throw new PublisherError("bad_request", `invalid request: \`op\` ${MUST_BE_AN_OP}`);
  }
}

/** Answers one request line with one reply line; never throws and never writes stdout. */
export async function handleLine(config: Config, line: string): Promise<string> {
  let id: number | null = null;
  try {
    const body = jsonObject(line);
    id = readId(body);
    return JSON.stringify(await answer(config, body));
  } catch (error) {
    const named = error instanceof PublisherError;
    const code: ErrorCode = named ? error.code : "internal";
    // A `bad_request` is the caller's own doing; anything else keeps its cause chain
    // here, where the wire cannot carry it.
    if (code !== "bad_request") {
      const evidence = named && error.cause !== undefined ? error.cause : error;
      console.error(`request failed code=${code} id=${id}: ${describeFailure(evidence).slice(0, 4_000)}`);
    }
    return JSON.stringify({ id, ok: false, code, message: named ? error.message : describeFailure(error) });
  }
}
