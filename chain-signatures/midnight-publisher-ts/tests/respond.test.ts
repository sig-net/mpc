// `POST /respond` request contract, offline. These tests are the seam's
// specification: every acceptance, every rejection with its exact body, and the
// JSON-shape negatives, all decided by one schema.

import { describe, expect, it } from "vitest";

import type { Config } from "../src/config.js";
import {
  handleRespond,
  respondCall,
  parseRespondRequest,
  type RespondBidirectionalEvent,
  type RespondCall,
  type SignatureRespondedEvent,
  type WireSignature,
} from "../src/respond.js";
import { describeFailure } from "../src/errors.js";
import { deriveFundingKeys, nodeConfig, parseFundingSeed } from "../src/wallet.js";
import { forbiddenClient, TEST_CONFIG } from "./support.js";

const ADDRESS = "ab".repeat(32);
const REQUEST_ID = "11".repeat(32);

// Loose on purpose: half the cases below are values the wire type does not admit.
type Body = Record<string, unknown>;

const SIGNATURE: WireSignature = {
  big_r: { x: "22".repeat(32), y: "33".repeat(32) },
  s: "44".repeat(32),
  recovery_id: 1,
};

const withSignature = (delta: Body): Body => ({ ...SIGNATURE, ...delta });

function signatureResponse(overrides: Body = {}): Body {
  return {
    contract_address: ADDRESS,
    circuit: "respond",
    request_id: REQUEST_ID,
    signature: SIGNATURE,
    ...overrides,
  };
}

function bidirectional(overrides: Body = {}): Body {
  return {
    contract_address: ADDRESS,
    circuit: "respondBidirectional",
    request_id: REQUEST_ID,
    serialized_output: "55".repeat(128),
    output_len: 64,
    signature: { ...SIGNATURE, recovery_id: 0 },
    ...overrides,
  };
}

// `JSON.stringify` drops a key set to `undefined`, so the rows below spell an omission `{ field: undefined }`.
const parse = (body: Body) => parseRespondRequest(JSON.stringify(body));

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

function signatureEvent(body: Body): SignatureRespondedEvent {
  const call = respondCall(parse(body));
  expect(call.circuitId).toBe("respond");
  return (call as Extract<RespondCall, { circuitId: "respond" }>).args[1];
}

function bidirectionalEvent(body: Body): RespondBidirectionalEvent {
  const call = respondCall(parse(body));
  expect(call.circuitId).toBe("respondBidirectional");
  return (call as Extract<RespondCall, { circuitId: "respondBidirectional" }>).args[1];
}

// Both ends of every bounded field, which the round-trip cases below do not reach.
describe("parseRespondRequest: accepts", () => {
  it("output_len at both ends of its range", () => {
    expect(() => parse(bidirectional({ output_len: 0 }))).not.toThrow();
    expect(() => parse(bidirectional({ output_len: 128 }))).not.toThrow();
  });

  it("recovery_id 0 and 1 on both circuits", () => {
    expect(() => parse(signatureResponse({ signature: withSignature({ recovery_id: 0 }) }))).not.toThrow();
    expect(() => parse(bidirectional({ signature: withSignature({ recovery_id: 1 }) }))).not.toThrow();
  });
});

// Every rejection, with the exact 400 body. One message per field.
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

  // ---- respond carries neither bidirectional field ----
  // `output_len: 0` is the trap: falsy, so a truthiness test would wave it

  // ---- respondBidirectional requires both ----
  ["serialized_output absent", bidirectional({ serialized_output: undefined }), "invalid request: `serialized_output` must be 256 lowercase hex (Bytes<128>)"],
  ["serialized_output 254 hex", bidirectional({ serialized_output: "55".repeat(127) }), "invalid request: `serialized_output` must be 256 lowercase hex (Bytes<128>)"],
  ["serialized_output uppercase", bidirectional({ serialized_output: "AA".repeat(128) }), "invalid request: `serialized_output` must be 256 lowercase hex (Bytes<128>)"],
  ["output_len absent", bidirectional({ output_len: undefined }), "invalid request: `output_len` must be an integer in 0..=128"],
  ["output_len 129", bidirectional({ output_len: 129 }), "invalid request: `output_len` must be an integer in 0..=128"],
  ["output_len 255", bidirectional({ output_len: 255 }), "invalid request: `output_len` must be an integer in 0..=128"],
  ["output_len negative", bidirectional({ output_len: -1 }), "invalid request: `output_len` must be an integer in 0..=128"],
  ["output_len fractional", bidirectional({ output_len: 1.5 }), "invalid request: `output_len` must be an integer in 0..=128"],

  // ---- circuit names ----
  ["an unrecognized circuit name", signatureResponse({ circuit: "respondBi" }), "invalid request: `circuit` must be respond or respondBidirectional"],
  ["empty circuit", signatureResponse({ circuit: "" }), "invalid request: `circuit` must be respond or respondBidirectional"],
  ["wrong case", signatureResponse({ circuit: "Respond" }), "invalid request: `circuit` must be respond or respondBidirectional"],
  ["the notify circuit is not postable here", signatureResponse({ circuit: "signBidirectional" }), "invalid request: `circuit` must be respond or respondBidirectional"],

  // ---- the three modes, on one field: absent, null, wrong type ----
  ["contract_address absent", signatureResponse({ contract_address: undefined }), "invalid request: `contract_address` must be 64 lowercase hex"],
  ["contract_address null", signatureResponse({ contract_address: null }), "invalid request: `contract_address` must be 64 lowercase hex"],
  ["contract_address as a number", signatureResponse({ contract_address: 1 }), "invalid request: `contract_address` must be 64 lowercase hex"],
  ["circuit absent", signatureResponse({ circuit: undefined }), "invalid request: `circuit` must be respond or respondBidirectional"],

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
    expect(() => parse(signatureResponse({ circuit: "nope", contract_address: "nope" }))).toThrowError(
      "invalid request: `circuit` must be respond or respondBidirectional",
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
  // `toEqual`, not `toStrictEqual`: an absent key and one set to `undefined` are
  // the same request.
  it("round-trips the respond body", () => {
    expect(parse(signatureResponse())).toEqual(signatureResponse());
  });

  it("round-trips the respondBidirectional body", () => {
    expect(parse(bidirectional())).toEqual(bidirectional());
  });

  // The branch declares neither field, so reaching for either is a compile error.
  // On the wire they are simply unknown keys.
  it("strips a bidirectional field sent to respond rather than rejecting it", () => {
    expect(parse(signatureResponse({ serialized_output: "55".repeat(128), output_len: 64 }))).toEqual(signatureResponse());
  });

  it("ignores unknown fields as the wire always has, and strips them rather than passing them on", () => {
    expect(parse({ ...bidirectional(), output_hash: "deadbeef", extra: 1 })).toEqual(bidirectional());
  });

  it.each(MALFORMED_BODIES)("rejects %s with an invalid-JSON message", (_label, body) => {
    expect(() => parseRespondRequest(body)).toThrowError(/^invalid JSON:/);
  });
});

// Field names are the Compact declaration's, numeric members are `bigint`, and
// the wire's big-endian bytes land in the nested `Signature` struct verbatim.
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

// The exact wire bodies this seam accepts. If the field set drifts, one of these fails.
describe("wire fixtures", () => {
  it("accepts the pinned respond body", () => {
    const body =
      `{"contract_address":"${ADDRESS}","circuit":"respond","request_id":"${REQUEST_ID}",` +
      `"signature":{"big_r":{"x":"2222222222222222222222222222222222222222222222222222222222222222","y":"3333333333333333333333333333333333333333333333333333333333333333"},"s":"4444444444444444444444444444444444444444444444444444444444444444","recovery_id":1}}`;
    expect(parseRespondRequest(body)).toEqual(signatureResponse());
  });

  it("accepts the pinned respondBidirectional body byte for byte", () => {
    const body =
      `{"contract_address":"${ADDRESS}","circuit":"respondBidirectional","request_id":"${REQUEST_ID}",` +
      `"serialized_output":"${"55".repeat(128)}","output_len":64,` +
      `"signature":{"big_r":{"x":"${"22".repeat(32)}","y":"${"33".repeat(32)}"},"s":"${"44".repeat(32)}","recovery_id":0}}`;
    expect(parseRespondRequest(body)).toEqual(bidirectional());
  });

});

const forbidden = forbiddenClient("no I/O may happen for an invalid request");

const offlineConfig: Config = { ...TEST_CONFIG, managedDir: "/nonexistent" };

const BAD_REQUESTS: [string, string, string | RegExp][] = [
  ["a malformed body", "{", /^invalid JSON:/],
  // Pinned byte for byte, not prefix-matched: this is the one message a caller
  // sees for well-formed JSON that is not an object.
  ["a non-object body", "[]", "invalid JSON: expected a JSON object"],
  ["a bad address", JSON.stringify(bidirectional({ contract_address: "nope" })), "invalid request: `contract_address` must be 64 lowercase hex"],
  [
    "an unknown circuit",
    JSON.stringify(signatureResponse({ circuit: "respondBi" })),
    "invalid request: `circuit` must be respond or respondBidirectional",
  ],
];

describe("handleRespond: the bad_request path never touches the chain", () => {
  it.each(BAD_REQUESTS)("returns bad_request for %s", async (_label, body, expected) => {
    const reply = await handleRespond(offlineConfig, forbidden, body);
    expect(reply.status).toBe(400);
    const { code, message } = JSON.parse(reply.body) as { code: string; message: string };
    expect(code).toBe("bad_request");
    expect(message).toMatch(expected);
  });
});

// Nothing is retried in process, so the 502 body is the whole answer. The shapes
// below are the ones the write path actually throws.
describe("describeFailure", () => {
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
    // Renders inside the 502 path, where a second failure would replace the real one.
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

});

// Checksum-valid, so it is the one the library derivation DOES accept and the only case that pins the guard.
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

// The library derivation underneath ALSO accepts a BIP-39 mnemonic, PBKDF2-ing
// it into a different, unfunded wallet. The `parseFundingSeed` pre-check is the
// only thing stopping that, and dropping it fails here rather than later as an
// unexplained `could not balance dust`.
describe("deriveFundingKeys", () => {
  it("rejects a valid BIP-39 mnemonic, which the library derivation would accept", () => {
    expect(() => deriveFundingKeys(VALID_MNEMONIC, "undeployed")).toThrowError(/MIDNIGHT_PUB_FUNDING_SEED/);
  });

  it("derives from a hex seed", () => {
    expect(deriveFundingKeys("ab".repeat(32), "undeployed").shieldedSecretKeys.coinPublicKey).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("nodeConfig", () => {
  it("hands the facade the five fields it declares, and nothing else", () => {
    expect(Object.keys(nodeConfig(offlineConfig)).sort()).toStrictEqual([
      "indexerUrl",
      "indexerWsUrl",
      "networkId",
      "nodeUrl",
      "proofServerUrl",
    ]);
  });
});
