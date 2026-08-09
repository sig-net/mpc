// The wire: one JSON object per line in, one per line out. `id` is echoed so a
// caller can match a reply without relying on ordering, and so a rejection names
// the post it belongs to.
//
// TWO OPERATIONS, ONE DISCRIMINATOR. `op` selects between them and is OPTIONAL,
// absent meaning `build`: the build request predates it and the Rust client still
// sends none, so requiring it would be a breaking change on both sides at once for
// no gain. `submit` carries the intent a previous `build` returned.
//
// The Rust client mirrors these shapes exactly. Adding a field is additive; renaming
// or retyping one is a breaking change on both sides at once.

import { z } from "zod";

import { redactSeed, type Config } from "./config.js";
import { describeFailure, jsonObject, PublisherError, type ErrorCode } from "./errors.js";
import { buildIntent, type BuildIntentInput } from "./intent.js";
import { handleSubmit } from "./submit.js";

export type BuildRequest = { readonly id: number } & BuildIntentInput;

export type SubmitRequest = { readonly id: number; readonly intent: string };

export type Response =
  | { readonly id: number; readonly ok: true; readonly intent: string }
  | { readonly id: number; readonly ok: true; readonly txId: string; readonly blockHash: string }
  // `id` is null when the line carried no readable one: there is nothing honest to
  // echo, and a stand-in integer would collide with a real id.
  | { readonly id: number | null; readonly ok: false; readonly code: ErrorCode; readonly message: string };

// One message per field: absent, null, wrong type and wrong value are the same thing here.
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

// Whatever the chain returned, so the length is the caller's business and only the
// alphabet and the byte boundary are checkable here.
const ledgerHex = z.string(MUST_BE_LEDGER_HEX).regex(/^(?:[0-9a-f]{2})+$/, MUST_BE_LEDGER_HEX);

// SEC1 BIG-ENDIAN hex, reaching the ledger untouched: this process converts nothing.
const wireSignature = wireObject({
  bigR: wireObject({ x: hex32, y: hex32 }),
  s: hex32,
  recoveryId: z.literal([0, 1], "must be 0|1"),
});

// JSON has one number type and `JSON.parse` silently rounds past 2^53, so an id above
// it comes back as a DIFFERENT integer and the echo would match a post nobody sent.
// Rejecting the range is the only defence available to a JSON wire: the Rust side must
// keep its ids inside it.
const wireId = z
  .int(MUST_BE_AN_ID)
  .nonnegative(MUST_BE_AN_ID)
  .max(Number.MAX_SAFE_INTEGER, MUST_BE_AN_ID);

// The pinned reads and the clock, all supplied: that is what keeps this a pure
// function and lets the caller keep the funding key.
const pinned = {
  contractState: ledgerHex,
  ledgerParameters: ledgerHex,
  // The funding wallet's Zswap public key. Public, and the only thing about that
  // wallet this process is ever told.
  coinPublicKey: hex32,
  ttlSeconds: z.int(MUST_BE_A_TTL).positive(MUST_BE_A_TTL),
};

// Whatever `build` handed back, so only the alphabet and the byte boundary are
// checkable here; the ledger's own tagged reader decides the rest.
const SubmitSchema = wireObject({ id: wireId, intent: ledgerHex });

// Field order is wire contract: only the first issue is surfaced and zod reports
// them in declaration order.
const BuildSchema = wireObject({
  id: wireId,
  contractAddress: hex32,
  circuit: z.literal(["respond", "respondBidirectional"], MUST_BE_A_CIRCUIT),
  requestId: hex32,
  signature: wireSignature,
  ...pinned,
});

// Deliberately not `jsonObject`'s `invalid JSON:`: past that point the JSON is fine and the request is not.
function toBadRequest(error: z.ZodError): PublisherError {
  const issue = error.issues[0]!;
  const path = issue.path.join(".");
  return new PublisherError("bad_request", `invalid request: ${path.length === 0 ? "" : `\`${path}\` `}${issue.message}`);
}

// The declared return types are the check that keeps the wire and the builder in
// step: a field renamed on one side alone is a type error here, not a runtime undefined.
function parseBuild(body: Record<string, unknown>): BuildRequest {
  const parsed = BuildSchema.safeParse(body);
  if (!parsed.success) throw toBadRequest(parsed.error);
  return parsed.data;
}

function parseSubmit(body: Record<string, unknown>): SubmitRequest {
  const parsed = SubmitSchema.safeParse(body);
  if (!parsed.success) throw toBadRequest(parsed.error);
  return parsed.data;
}

// Absent is `build`, which is what keeps the pre-discriminator request working. Read
// before either schema, so an unknown operation is named rather than reported as a
// missing `circuit`.
function readOp(body: Record<string, unknown>): "build" | "submit" {
  const op = body["op"];
  if (op === undefined || op === "build") return "build";
  if (op === "submit") return "submit";
  throw new PublisherError("bad_request", `invalid request: \`op\` ${MUST_BE_AN_OP}`);
}

// Best effort, and it runs before validation: a rejected request still has to say
// which post it was. `isSafeInteger` is what makes the echo trustworthy rather than
// merely present: past 2^53 the parsed value is no longer the one that was sent.
function readId(body: Record<string, unknown>): number | null {
  const id = body["id"];
  return typeof id === "number" && Number.isSafeInteger(id) ? id : null;
}

// `JSON.stringify` escapes every newline it emits, so one response is always one line.
// Redacted on the way out because this is the last point every reply passes through,
// and the funding seed reaching a reply line would put it in the parent node's log.
const encode = (response: Response): string => redactSeed(JSON.stringify(response));

async function answer(config: Config, body: Record<string, unknown>): Promise<Response> {
  if (readOp(body) === "submit") {
    const request = parseSubmit(body);
    const landed = await handleSubmit(config, request.id, Buffer.from(request.intent, "hex"));
    return { id: request.id, ok: true, txId: landed.txId, blockHash: landed.blockHash };
  }
  const request = parseBuild(body);
  const intent = await buildIntent(config.managedDir, request);
  return { id: request.id, ok: true, intent: Buffer.from(intent).toString("hex") };
}

/**
 * Answers one request line with one reply line. Never throws and never writes to
 * stdout: the caller owns the framing, and a thrown error would strand a request
 * the caller is still waiting on.
 */
export async function handleLine(config: Config, line: string): Promise<string> {
  let id: number | null = null;
  try {
    const body = jsonObject(line);
    id = readId(body);
    return encode(await answer(config, body));
  } catch (error) {
    const named = error instanceof PublisherError;
    const code: ErrorCode = named ? error.code : "internal";
    // A `bad_request` is the caller's own doing and its message says everything;
    // anything else keeps its cause chain here, where the wire cannot carry it.
    if (code !== "bad_request") {
      const evidence = named && error.cause !== undefined ? error.cause : error;
      console.error(redactSeed(`request failed [${code}] id=${id}: ${describeFailure(evidence).slice(0, 4_000)}`));
    }
    return encode({ id, ok: false, code, message: named ? error.message : describeFailure(error) });
  }
}
