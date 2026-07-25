/**
 * `POST /respond` request contract. Everything here runs offline: no node, no
 * indexer, no proof server, no wallet. The live prove-and-submit is a script,
 * `tests/respond-live.ts`.
 *
 * These tests are the seam's specification: every acceptance, every rejection
 * with its exact body, and the JSON-shape negatives (absent, `null`, wrong
 * types, unknown fields, check ordering), all of it decided by one schema.
 */

import { GENESIS_MINT_WALLET_SEED } from "@sig-net/midnight-contract-deploy";
import { describe, expect, it } from "vitest";

import type { Config } from "../src/config.js";
import {
  describeFailure,
  handleRespond,
  respondCall,
  parseRespondRequest,
  type RespondBidirectionalEvent,
  type RespondCall,
  type RespondCircuit,
  type SignatureRespondedEvent,
  type WireSignature,
} from "../src/respond.js";
import { deriveFundingKeys, parseFundingSeed } from "../src/wallet.js";
import { forbiddenClient, TEST_CONFIG } from "./support.js";

const ADDRESS = "ab".repeat(32);
const REQUEST_ID = "11".repeat(32);

/** Loose on purpose: half the cases below are values the wire type does not admit. */
type Body = Record<string, unknown>;

/** The shared signature both circuits carry; typed, so the schema's own shape pins it. */
const SIGNATURE: WireSignature = {
  big_r: { x: "22".repeat(32), y: "33".repeat(32) },
  s: "44".repeat(32),
  recovery_id: 1,
};

/** SIGNATURE with one component replaced, for the rejection rows. */
const withSignature = (delta: Body): Body => ({ ...SIGNATURE, ...delta });

/** A valid `postSignatureResponse` request, with fields optionally replaced. */
function signatureResponse(overrides: Body = {}): Body {
  return {
    contract_address: ADDRESS,
    circuit: "postSignatureResponse",
    request_id: REQUEST_ID,
    signature: SIGNATURE,
    ...overrides,
  };
}

/** A valid `postRespondBidirectional` request, with fields optionally replaced. */
function bidirectional(overrides: Body = {}): Body {
  return {
    contract_address: ADDRESS,
    circuit: "postRespondBidirectional",
    request_id: REQUEST_ID,
    serialized_output: "55".repeat(128),
    output_len: 64,
    signature: { ...SIGNATURE, recovery_id: 0 },
    ...overrides,
  };
}

/** `JSON.stringify` drops a key set to `undefined`, so the rows below spell an omission `{ field: undefined }`. */
const parse = (body: Body) => parseRespondRequest(JSON.stringify(body));

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

/** Parse, then take the event argument of a `postSignatureResponse` call. */
function signatureEvent(body: Body): SignatureRespondedEvent {
  const call = respondCall(parse(body));
  expect(call.circuitId).toBe("postSignatureResponse");
  // Safe after the assertion above; the union cannot be narrowed by `expect`.
  return (call as Extract<RespondCall, { circuitId: "postSignatureResponse" }>).args[1];
}

/** Parse, then take the event argument of a `postRespondBidirectional` call. */
function bidirectionalEvent(body: Body): RespondBidirectionalEvent {
  const call = respondCall(parse(body));
  expect(call.circuitId).toBe("postRespondBidirectional");
  return (call as Extract<RespondCall, { circuitId: "postRespondBidirectional" }>).args[1];
}

describe("parseRespondRequest: accepts", () => {
  it("a well-formed postSignatureResponse", () => {
    expect(() => parse(signatureResponse())).not.toThrow();
  });

  it("a well-formed postRespondBidirectional", () => {
    expect(() => parse(bidirectional())).not.toThrow();
  });

  it("output_len at both ends of its range", () => {
    expect(() => parse(bidirectional({ output_len: 0 }))).not.toThrow();
    expect(() => parse(bidirectional({ output_len: 128 }))).not.toThrow();
  });

  it("recovery_id 0 and 1 on both circuits", () => {
    expect(() => parse(signatureResponse({ signature: withSignature({ recovery_id: 0 }) }))).not.toThrow();
    expect(() => parse(bidirectional({ signature: withSignature({ recovery_id: 1 }) }))).not.toThrow();
  });
});

/**
 * Every rejection, with the exact 400 body. One message per field, so the value
 * rows and the shape rows below say the same sentence and neither needs to
 * re-cross the other's cases.
 */
const REJECTIONS: [string, Body, string][] = [
  // ---- the address and the request id ----
  ["address too short", signatureResponse({ contract_address: "ab".repeat(31) }), "invalid request: `contract_address` must be 64 lowercase hex"],
  ["address uppercase", signatureResponse({ contract_address: "AB".repeat(32) }), "invalid request: `contract_address` must be 64 lowercase hex"],
  ["address empty", signatureResponse({ contract_address: "" }), "invalid request: `contract_address` must be 64 lowercase hex"],
  ["address non-hex", signatureResponse({ contract_address: "zz".repeat(32) }), "invalid request: `contract_address` must be 64 lowercase hex"],
  ["address 0x-prefixed", signatureResponse({ contract_address: `0x${"ab".repeat(32)}` }), "invalid request: `contract_address` must be 64 lowercase hex"],
  ["request id too long", signatureResponse({ request_id: "11".repeat(33) }), "invalid request: `request_id` must be 64 lowercase hex"],
  ["request id uppercase", signatureResponse({ request_id: "AA".repeat(32) }), "invalid request: `request_id` must be 64 lowercase hex"],

  // ---- the signature, named component by component ----
  ["big_r.x uppercase", signatureResponse({ signature: withSignature({ big_r: { x: "AA".repeat(32), y: "33".repeat(32) } }) }), "invalid request: `signature.big_r.x` must be 64 lowercase hex"],
  ["big_r.x short", signatureResponse({ signature: withSignature({ big_r: { x: "22".repeat(31), y: "33".repeat(32) } }) }), "invalid request: `signature.big_r.x` must be 64 lowercase hex"],
  ["big_r.y short", signatureResponse({ signature: withSignature({ big_r: { x: "22".repeat(32), y: "33".repeat(31) } }) }), "invalid request: `signature.big_r.y` must be 64 lowercase hex"],
  ["s uppercase", signatureResponse({ signature: withSignature({ s: "AA".repeat(32) }) }), "invalid request: `signature.s` must be 64 lowercase hex"],
  ["s empty", signatureResponse({ signature: withSignature({ s: "" }) }), "invalid request: `signature.s` must be 64 lowercase hex"],
  ["the same signature rejected on the other circuit", bidirectional({ signature: withSignature({ s: "AA".repeat(32) }) }), "invalid request: `signature.s` must be 64 lowercase hex"],
  ["recovery_id 2", signatureResponse({ signature: withSignature({ recovery_id: 2 }) }), "invalid request: `signature.recovery_id` must be 0|1"],
  ["recovery_id 255", signatureResponse({ signature: withSignature({ recovery_id: 255 }) }), "invalid request: `signature.recovery_id` must be 0|1"],
  ["recovery_id negative", signatureResponse({ signature: withSignature({ recovery_id: -1 }) }), "invalid request: `signature.recovery_id` must be 0|1"],
  ["recovery_id fractional", signatureResponse({ signature: withSignature({ recovery_id: 0.5 }) }), "invalid request: `signature.recovery_id` must be 0|1"],

  // ---- postSignatureResponse carries neither bidirectional field ----
  // `output_len: 0` is the trap: falsy, so a truthiness test would wave it
  // through. The branch declares the field absent, so no value enters it.
  ["contaminated with serialized_output", signatureResponse({ serialized_output: "55".repeat(128) }), "invalid request: `serialized_output` must be absent on postSignatureResponse"],
  ["contaminated with output_len", signatureResponse({ output_len: 64 }), "invalid request: `output_len` must be absent on postSignatureResponse"],
  ["contaminated with output_len 0", signatureResponse({ output_len: 0 }), "invalid request: `output_len` must be absent on postSignatureResponse"],

  // ---- postRespondBidirectional requires both ----
  ["serialized_output absent", bidirectional({ serialized_output: undefined }), "invalid request: `serialized_output` must be 256 lowercase hex (Bytes<128>)"],
  ["serialized_output 254 hex", bidirectional({ serialized_output: "55".repeat(127) }), "invalid request: `serialized_output` must be 256 lowercase hex (Bytes<128>)"],
  ["serialized_output uppercase", bidirectional({ serialized_output: "AA".repeat(128) }), "invalid request: `serialized_output` must be 256 lowercase hex (Bytes<128>)"],
  ["output_len absent", bidirectional({ output_len: undefined }), "invalid request: `output_len` must be an integer in 0..=128"],
  ["output_len 129", bidirectional({ output_len: 129 }), "invalid request: `output_len` must be an integer in 0..=128"],
  ["output_len 255", bidirectional({ output_len: 255 }), "invalid request: `output_len` must be an integer in 0..=128"],
  ["output_len negative", bidirectional({ output_len: -1 }), "invalid request: `output_len` must be an integer in 0..=128"],
  ["output_len fractional", bidirectional({ output_len: 1.5 }), "invalid request: `output_len` must be an integer in 0..=128"],

  // ---- circuit names ----
  ["an unrecognized circuit name", signatureResponse({ circuit: "postRespond" }), "invalid request: `circuit` must be postSignatureResponse or postRespondBidirectional"],
  ["empty circuit", signatureResponse({ circuit: "" }), "invalid request: `circuit` must be postSignatureResponse or postRespondBidirectional"],
  ["wrong case", signatureResponse({ circuit: "postsignatureresponse" }), "invalid request: `circuit` must be postSignatureResponse or postRespondBidirectional"],
  ["the notify circuit is not postable here", signatureResponse({ circuit: "signBidirectionalEvent" }), "invalid request: `circuit` must be postSignatureResponse or postRespondBidirectional"],

  // ---- the three modes, on one field: absent, null, wrong type ----
  ["contract_address absent", signatureResponse({ contract_address: undefined }), "invalid request: `contract_address` must be 64 lowercase hex"],
  ["contract_address null", signatureResponse({ contract_address: null }), "invalid request: `contract_address` must be 64 lowercase hex"],
  ["contract_address as a number", signatureResponse({ contract_address: 1 }), "invalid request: `contract_address` must be 64 lowercase hex"],
  ["circuit absent", signatureResponse({ circuit: undefined }), "invalid request: `circuit` must be postSignatureResponse or postRespondBidirectional"],

  // ---- each type, at each nesting depth ----
  ["signature as a string", signatureResponse({ signature: "nope" }), "invalid request: `signature` must be an object"],
  ["signature as an array", signatureResponse({ signature: [] }), "invalid request: `signature` must be an object"],
  ["signature null", signatureResponse({ signature: null }), "invalid request: `signature` must be an object"],
  ["signature.big_r absent", signatureResponse({ signature: { s: SIGNATURE.s, recovery_id: 1 } }), "invalid request: `signature.big_r` must be an object"],
  ["signature.big_r.x as a number", signatureResponse({ signature: withSignature({ big_r: { x: 1, y: SIGNATURE.big_r.y } }) }), "invalid request: `signature.big_r.x` must be 64 lowercase hex"],
  ["signature.s null", signatureResponse({ signature: withSignature({ s: null }) }), "invalid request: `signature.s` must be 64 lowercase hex"],
  ["signature.recovery_id as a string", signatureResponse({ signature: withSignature({ recovery_id: "1" }) }), "invalid request: `signature.recovery_id` must be 0|1"],
  ["serialized_output as a number", bidirectional({ serialized_output: 1 }), "invalid request: `serialized_output` must be 256 lowercase hex (Bytes<128>)"],
  ["serialized_output null", bidirectional({ serialized_output: null }), "invalid request: `serialized_output` must be 256 lowercase hex (Bytes<128>)"],
  ["output_len null", bidirectional({ output_len: null }), "invalid request: `output_len` must be an integer in 0..=128"],
  ["output_len as a string", bidirectional({ output_len: "64" }), "invalid request: `output_len` must be an integer in 0..=128"],
];

describe.each(REJECTIONS)("parseRespondRequest rejects %s", (_label, body, message) => {
  it(`with "${message}"`, () => {
    expect(() => parse(body)).toThrowError(message);
  });
});

describe("parseRespondRequest: checks fire in their pinned wire order", () => {
  it("answers the circuit before ANY other field, because it is the discriminator", () => {
    // No branch matched, so no branch's fields were ever looked at.
    expect(() => parse(signatureResponse({ circuit: "nope", contract_address: "nope" }))).toThrowError(
      "invalid request: `circuit` must be postSignatureResponse or postRespondBidirectional",
    );
  });

  it("reports the address before the request id", () => {
    expect(() => parse(signatureResponse({ contract_address: "nope", request_id: "nope" }))).toThrowError(
      "invalid request: `contract_address` must be 64 lowercase hex",
    );
  });

  it("reports the request id before the signature", () => {
    expect(() =>
      parse(signatureResponse({ request_id: "nope", signature: withSignature({ s: "nope" }) })),
    ).toThrowError("invalid request: `request_id` must be 64 lowercase hex");
  });

  it("reports a malformed scalar before a bad recovery id", () => {
    expect(() =>
      parse(signatureResponse({ signature: withSignature({ s: "zz".repeat(32), recovery_id: 9 }) })),
    ).toThrowError("invalid request: `signature.s` must be 64 lowercase hex");
  });

  it("reports the signature before the circuit's own fields", () => {
    // The signature is shared, so it is declared before the fields that split.
    expect(() =>
      parse(bidirectional({ signature: withSignature({ s: "" }), serialized_output: "55" })),
    ).toThrowError("invalid request: `signature.s` must be 64 lowercase hex");
  });

  it("reports a bad serialized_output before a bad output_len", () => {
    expect(() => parse(bidirectional({ serialized_output: "55", output_len: 200 }))).toThrowError(
      "invalid request: `serialized_output` must be 256 lowercase hex (Bytes<128>)",
    );
  });
});

const MALFORMED_BODIES: [string, string][] = [
  ["not JSON at all", "{"],
  ["a JSON array", "[]"],
  ["a bare string", '"hello"'],
  ["a bare number", "7"],
  ["null", "null"],
  ["an empty body", ""],
];

describe("parseRespondRequest", () => {
  // `toEqual`, not `toStrictEqual`: an absent optional key and one set to
  // `undefined` are the same request, and the schema omits what it did not see.
  it("round-trips the postSignatureResponse body", () => {
    expect(parse(signatureResponse())).toEqual(signatureResponse());
  });

  it("round-trips the postRespondBidirectional body", () => {
    expect(parse(bidirectional())).toEqual(bidirectional());
  });

  it("omitting an optional field is the way to leave it out", () => {
    const parsed = parse(signatureResponse());
    expect(parsed.serialized_output).toBeUndefined();
    expect(parsed.output_len).toBeUndefined();
  });

  it("ignores unknown fields, as the wire always has", () => {
    expect(() => parse({ ...bidirectional(), output_hash: "deadbeef", extra: 1 })).not.toThrow();
  });

  it("strips the unknown fields rather than passing them on", () => {
    expect(parse({ ...bidirectional(), output_hash: "deadbeef" })).toEqual(bidirectional());
  });

  it.each(MALFORMED_BODIES)("rejects %s with an invalid-JSON message", (_label, body) => {
    // Never reaches the schema, so it keeps the `invalid JSON:` preamble.
    expect(() => parseRespondRequest(body)).toThrowError(/^invalid JSON:/);
  });
});

/**
 * Both circuits take exactly two arguments: the request id, then the whole
 * event struct. The struct's field names are the Compact declaration's, its
 * numeric members are `bigint` (`Uint<N>` generates as `bigint`), and the
 * signature is the nested `Signature { bigR: { x, y }, s, recoveryId }`
 * struct — the wire's big-endian bytes land in it verbatim.
 */
describe("respondCall", () => {
  it("builds requestId plus one SignatureRespondedEvent", () => {
    const call = respondCall(parse(signatureResponse()));

    expect(call.args).toHaveLength(2);
    expect(hex(call.args[0])).toBe(REQUEST_ID);
    const event = signatureEvent(signatureResponse());
    expect(Object.keys(event)).toStrictEqual(["signature"]);
    expect(Object.keys(event.signature).sort()).toStrictEqual(["bigR", "recoveryId", "s"]);
    expect(Object.keys(event.signature.bigR).sort()).toStrictEqual(["x", "y"]);
  });

  it("carries the wire's big-endian components into the struct unchanged", () => {
    const event = signatureEvent(signatureResponse());

    expect(hex(event.signature.bigR.x)).toBe("22".repeat(32));
    expect(hex(event.signature.bigR.y)).toBe("33".repeat(32));
    expect(hex(event.signature.s)).toBe("44".repeat(32));
    expect(event.signature.recoveryId).toBe(1n);
  });

  it("builds requestId plus one RespondBidirectionalEvent", () => {
    const call = respondCall(parse(bidirectional()));

    expect(hex(call.args[0])).toBe(REQUEST_ID);
    const event = bidirectionalEvent(bidirectional());
    expect(Object.keys(event).sort()).toStrictEqual([
      "outputLen",
      "serializedOutput",
      "signature",
    ]);
    expect(hex(event.signature.bigR.x)).toBe("22".repeat(32));
    expect(hex(event.signature.bigR.y)).toBe("33".repeat(32));
    expect(hex(event.signature.s)).toBe("44".repeat(32));
    expect(event.signature.recoveryId).toBe(0n);
  });

  it("keeps serializedOutput at its full 128 bytes and outputLen as a bigint", () => {
    const event = bidirectionalEvent(bidirectional());

    expect(event.serializedOutput).toHaveLength(128);
    expect(hex(event.serializedOutput)).toBe("55".repeat(128));
    expect(event.outputLen).toBe(64n);
    expect(typeof event.outputLen).toBe("bigint");
  });
});

/** The exact wire bodies this seam accepts, byte for byte. If the field set drifts, one of these fails. */
describe("wire fixtures", () => {
  it("accepts the pinned postSignatureResponse body", () => {
    const body =
      `{"contract_address":"${ADDRESS}","circuit":"postSignatureResponse","request_id":"${REQUEST_ID}",` +
      `"signature":{"big_r":{"x":"2222222222222222222222222222222222222222222222222222222222222222","y":"3333333333333333333333333333333333333333333333333333333333333333"},"s":"4444444444444444444444444444444444444444444444444444444444444444","recovery_id":1}}`;
    expect(() => parseRespondRequest(body)).not.toThrow();
  });

  it("accepts the pinned postRespondBidirectional body byte for byte", () => {
    const body =
      `{"contract_address":"${ADDRESS}","circuit":"postRespondBidirectional","request_id":"${REQUEST_ID}",` +
      `"serialized_output":"${"55".repeat(128)}","output_len":64,` +
      `"signature":{"big_r":{"x":"${"22".repeat(32)}","y":"${"33".repeat(32)}"},"s":"${"44".repeat(32)}","recovery_id":0}}`;
    expect(parseRespondRequest(body)).toEqual(bidirectional());
  });

});

const forbidden = forbiddenClient("no I/O may happen for an invalid request");

/** A managed dir that cannot resolve, so reaching boot at all is a visible failure. */
const offlineConfig: Config = {
  ...TEST_CONFIG,
  managedDir: "/nonexistent",
  fundingSeed: GENESIS_MINT_WALLET_SEED,
};

const BAD_REQUESTS: [string, string, string | RegExp][] = [
  ["a malformed body", "{", /^invalid JSON:/],
  ["a bad address", JSON.stringify(bidirectional({ contract_address: "nope" })), "invalid request: `contract_address` must be 64 lowercase hex"],
  [
    "an unknown circuit",
    JSON.stringify(signatureResponse({ circuit: "postRespond" })),
    "invalid request: `circuit` must be postSignatureResponse or postRespondBidirectional",
  ],
  [
    "a contaminated body",
    JSON.stringify(signatureResponse({ serialized_output: "55".repeat(128) })),
    "invalid request: `serialized_output` must be absent on postSignatureResponse",
  ],
];

describe("the JSON preamble", () => {
  it("is byte-identical on this seam, not merely prefix-matched", () => {
    // Shared with `/decode/contract-state`; pinned on both sides so unifying
    // them cannot silently move one.
    expect(() => parseRespondRequest("[]")).toThrow("invalid JSON: expected a JSON object");
  });
});

describe("handleRespond: the bad_request path never touches the chain", () => {
  it.each(BAD_REQUESTS)("returns bad_request for %s", async (_label, body, expected) => {
    const reply = await handleRespond(offlineConfig, forbidden, body);
    expect(reply.status).toBe(400);
    // The code is the stable half and the message is the free half; a caller
    // branches on the first and shows the second.
    const { code, message } = JSON.parse(reply.body) as { code: string; message: string };
    expect(code).toBe("bad_request");
    expect(message).toMatch(expected);
  });
});

/**
 * Nothing is retried in process, so the 502 body is the whole answer a caller
 * gets and must name the failure. The shapes below are the ones the write path
 * actually throws: an Effect `FiberFailure`, whose `name` carries the failing
 * class and whose `message` carries only the bare text (a live same-id race
 * returned `(FiberFailure) Wallet.InsufficientFunds: Insufficient Funds: could
 * not balance dust`); a wrapper with a `cause`; and a tagged value that is not
 * an `Error` at all.
 */
describe("describeFailure", () => {
  it("keeps the tag the node's rejection carries in its name", () => {
    const rejected = new Error("Transaction is invalid and was rejected by the node");
    rejected.name = "(FiberFailure) TransactionInvalidError";
    expect(describeFailure(rejected)).toBe(
      "(FiberFailure) TransactionInvalidError: Transaction is invalid and was rejected by the node",
    );
  });

  it("leaves a plain Error's message unadorned", () => {
    expect(describeFailure(new Error("prove failed: 500 Internal Server Error"))).toBe(
      "prove failed: 500 Internal Server Error",
    );
  });

  it("appends a cause instead of dropping it", () => {
    const wrapped = new Error("balancing failed", { cause: { _tag: "TransactionInvalidError", message: "rejected" } });
    expect(describeFailure(wrapped)).toBe("balancing failed: TransactionInvalidError: rejected");
  });

  it("does not repeat a cause the wrapper already quoted", () => {
    expect(describeFailure(new Error("submit failed: rejected", { cause: new Error("rejected") }))).toBe(
      "submit failed: rejected",
    );
  });

  it("renders a thrown non-Error rather than [object Object]", () => {
    expect(describeFailure({ _tag: "ConnectionError", message: "socket hang up" })).toBe(
      "ConnectionError: socket hang up",
    );
    expect(describeFailure({ code: -32000 })).toBe(`{"code":-32000}`);
    expect(describeFailure("boom")).toBe("boom");
    expect(describeFailure(undefined)).toBe("undefined");
  });

  it("never throws itself, whatever it is handed", () => {
    // Renders inside the 502 path, where a second failure would replace the
    // real one. Neither an object that cannot be serialized nor one that
    // serializes to nothing may escape.
    const circular: { self?: unknown } = {};
    circular.self = circular;
    expect(describeFailure(circular)).toBe("[object Object]");
    expect(describeFailure({ toJSON: () => undefined })).toBe("[object Object]");
  });

  it("stops walking, so a pathological chain cannot become the response body", () => {
    let chain: unknown = { message: "innermost" };
    for (let depth = 0; depth < 8; depth += 1) chain = { message: `link${depth}`, cause: chain };
    expect(describeFailure(chain)).not.toContain("innermost");
  });

  it("does not loop forever on a self-referential cause chain", () => {
    const looping: { message: string; cause?: unknown } = { message: "round and round" };
    looping.cause = looping;
    expect(describeFailure(looping)).toBe("round and round");
  });
});

/**
 * A real, checksum-valid 12-word BIP-39 mnemonic. Distinct from the malformed
 * phrase below on purpose: this is the one the library derivation underneath
 * `deriveFundingKeys` DOES accept, so it is the only case that pins the guard.
 */
const VALID_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const BAD_SEEDS: [string, string][] = [
  ["too short", "ab".repeat(15)],
  ["too long", "ab".repeat(65)],
  ["odd length", "abc"],
  ["a malformed mnemonic", "abandon abandon abandon abandon abandon abandon abandon about"],
  ["a valid BIP-39 mnemonic", VALID_MNEMONIC],
  ["empty", ""],
];

describe("parseFundingSeed", () => {
  it("accepts 32 bytes of hex, with or without 0x", () => {
    expect(parseFundingSeed("ab".repeat(32))).toHaveLength(32);
    expect(parseFundingSeed(`0x${"ab".repeat(32)}`)).toHaveLength(32);
    expect(parseFundingSeed(` ${"AB".repeat(32)} `)).toHaveLength(32);
  });

  it("accepts both ends of the accepted length range", () => {
    expect(parseFundingSeed("ab".repeat(16))).toHaveLength(16);
    expect(parseFundingSeed("ab".repeat(64))).toHaveLength(64);
  });

  it.each(BAD_SEEDS)("rejects %s", (_label, seed) => {
    expect(() => parseFundingSeed(seed)).toThrowError(/MIDNIGHT_PUB_FUNDING_SEED/);
  });

  it("never quotes the seed in its error, since the seed is the one secret held", () => {
    const seed = "c0ffee".repeat(3);
    expect(() => parseFundingSeed(seed)).toThrowError();
    expect(() => parseFundingSeed(seed)).not.toThrowError(seed);
  });
});

/**
 * `deriveFundingKeys` delegates to a library derivation whose own seed parser
 * ALSO accepts a BIP-39 mnemonic, PBKDF2-ing it into a different, unfunded
 * wallet. The `parseFundingSeed` pre-check is the only thing stopping that, and
 * dropping it fails here rather than six months later as an unexplained
 * `Wallet.InsufficientFunds: could not balance dust`.
 */
describe("deriveFundingKeys", () => {
  it("rejects a valid BIP-39 mnemonic, which the library derivation would accept", () => {
    expect(() => deriveFundingKeys(VALID_MNEMONIC, "undeployed")).toThrowError(/MIDNIGHT_PUB_FUNDING_SEED/);
  });

  it("derives from a hex seed", () => {
    expect(deriveFundingKeys("ab".repeat(32), "undeployed").shieldedSecretKeys.coinPublicKey).toMatch(/^[0-9a-f]{64}$/);
  });
});

/** The narrowing the parse performs is what keeps `respondCall` total. */
describe("types", () => {
  it("narrows the circuit to the two postable ids", () => {
    const request = parse(bidirectional());
    const circuit: RespondCircuit = request.circuit;
    expect(circuit).toBe("postRespondBidirectional");
    // Narrowed by the discriminant alone: no cast, no second check.
    if (request.circuit === "postRespondBidirectional") {
      const output: string = request.serialized_output;
      const length: number = request.output_len;
      expect(output).toHaveLength(256);
      expect(length).toBe(64);
    }
  });
});
