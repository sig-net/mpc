/**
 * `POST /respond` request contract. Everything here runs offline: no node, no
 * indexer, no proof server, no wallet. The live prove-and-submit is a script,
 * `tests/respond-live.ts`.
 *
 * These tests are the seam's specification: every acceptance, every rejection
 * with its exact body, and the JSON-shape negatives (wrong types, `null`
 * versus absent, unknown fields, check ordering).
 */

import { describe, expect, it } from "vitest";

import type { Config } from "../src/config.js";
import type { NodeClient } from "../src/node.js";
import {
  describeFailure,
  handleRespond,
  respondCall,
  validateRespondRequest,
  parseRespondRequest,
  type RespondBidirectionalEvent,
  type RespondCall,
  type RespondCircuit,
  type RespondRequest,
  type SignatureRespondedEvent,
  type WireSignature,
} from "../src/respond.js";
import { deriveFundingKeys, parseFundingSeed } from "../src/wallet.js";

const ADDRESS = "ab".repeat(32);
const REQUEST_ID = "11".repeat(32);

/** The shared signature both circuits carry; vary it with an explicit spread. */
const SIGNATURE: WireSignature = {
  big_r: { x: "22".repeat(32), y: "33".repeat(32) },
  s: "44".repeat(32),
  recovery_id: 1,
};

/** SIGNATURE with one component replaced, for the rejection rows. */
const withSignature = (delta: Partial<WireSignature>): WireSignature => ({ ...SIGNATURE, ...delta });

/** A valid `postSignatureResponse` request, with fields optionally replaced. */
function signatureResponse(overrides: Partial<RespondRequest> = {}): RespondRequest {
  return {
    contract_address: ADDRESS,
    circuit: "postSignatureResponse",
    request_id: REQUEST_ID,
    signature: SIGNATURE,
    ...overrides,
  };
}

/** A valid `postRespondBidirectional` request, with fields optionally replaced. */
function bidirectional(overrides: Partial<RespondRequest> = {}): RespondRequest {
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

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

/** Validate, then take the event argument of a `postSignatureResponse` call. */
function signatureEvent(request: RespondRequest): SignatureRespondedEvent {
  validateRespondRequest(request);
  const call = respondCall(request);
  expect(call.circuitId).toBe("postSignatureResponse");
  // Safe after the assertion above; the union cannot be narrowed by `expect`.
  return (call as Extract<RespondCall, { circuitId: "postSignatureResponse" }>).args[1];
}

/** Validate, then take the event argument of a `postRespondBidirectional` call. */
function bidirectionalEvent(request: RespondRequest): RespondBidirectionalEvent {
  validateRespondRequest(request);
  const call = respondCall(request);
  expect(call.circuitId).toBe("postRespondBidirectional");
  return (call as Extract<RespondCall, { circuitId: "postRespondBidirectional" }>).args[1];
}

describe("validateRespondRequest: accepts", () => {
  it("a well-formed postSignatureResponse", () => {
    expect(() => validateRespondRequest(signatureResponse())).not.toThrow();
  });

  it("a well-formed postRespondBidirectional", () => {
    expect(() => validateRespondRequest(bidirectional())).not.toThrow();
  });

  it("output_len at both ends of its range", () => {
    expect(() => validateRespondRequest(bidirectional({ output_len: 0 }))).not.toThrow();
    expect(() => validateRespondRequest(bidirectional({ output_len: 128 }))).not.toThrow();
  });

  it("recovery_id 0 and 1 on both circuits", () => {
    expect(() =>
      validateRespondRequest(signatureResponse({ signature: withSignature({ recovery_id: 0 }) })),
    ).not.toThrow();
    expect(() =>
      validateRespondRequest(bidirectional({ signature: withSignature({ recovery_id: 1 }) })),
    ).not.toThrow();
  });
});

/** Every rejection, with the exact 400 body. */
const REJECTIONS: [string, RespondRequest, string][] = [
  // ---- address and request id, checked before the circuit ----
  ["address too short", signatureResponse({ contract_address: "ab".repeat(31) }), "contract_address must be 64 lowercase hex"],
  ["address uppercase", signatureResponse({ contract_address: "AB".repeat(32) }), "contract_address must be 64 lowercase hex"],
  ["address empty", signatureResponse({ contract_address: "" }), "contract_address must be 64 lowercase hex"],
  ["address non-hex", signatureResponse({ contract_address: "zz".repeat(32) }), "contract_address must be 64 lowercase hex"],
  ["address 0x-prefixed", signatureResponse({ contract_address: `0x${"ab".repeat(32)}` }), "contract_address must be 64 lowercase hex"],
  ["request id too long", signatureResponse({ request_id: "11".repeat(33) }), "request_id must be 64 hex"],
  ["request id uppercase", signatureResponse({ request_id: "AA".repeat(32) }), "request_id must be 64 hex"],

  // ---- the signature, checked once for both circuits ----
  ["big_r.x uppercase", signatureResponse({ signature: withSignature({ big_r: { x: "AA".repeat(32), y: "33".repeat(32) } }) }), "signature.big_r.x, signature.big_r.y and signature.s must be 64 lowercase hex each"],
  ["big_r.x short", signatureResponse({ signature: withSignature({ big_r: { x: "22".repeat(31), y: "33".repeat(32) } }) }), "signature.big_r.x, signature.big_r.y and signature.s must be 64 lowercase hex each"],
  ["big_r.y short", signatureResponse({ signature: withSignature({ big_r: { x: "22".repeat(32), y: "33".repeat(31) } }) }), "signature.big_r.x, signature.big_r.y and signature.s must be 64 lowercase hex each"],
  ["s uppercase", signatureResponse({ signature: withSignature({ s: "AA".repeat(32) }) }), "signature.big_r.x, signature.big_r.y and signature.s must be 64 lowercase hex each"],
  ["s empty", signatureResponse({ signature: withSignature({ s: "" }) }), "signature.big_r.x, signature.big_r.y and signature.s must be 64 lowercase hex each"],
  ["the same signature rejected on the other circuit", bidirectional({ signature: withSignature({ s: "AA".repeat(32) }) }), "signature.big_r.x, signature.big_r.y and signature.s must be 64 lowercase hex each"],
  ["recovery_id 2", signatureResponse({ signature: withSignature({ recovery_id: 2 }) }), "signature.recovery_id must be 0|1"],
  ["recovery_id 255", signatureResponse({ signature: withSignature({ recovery_id: 255 }) }), "signature.recovery_id must be 0|1"],

  // ---- postSignatureResponse ----
  ["contaminated with serialized_output", signatureResponse({ serialized_output: "55".repeat(128) }), "postSignatureResponse takes no bidirectional fields"],
  ["contaminated with output_len", signatureResponse({ output_len: 64 }), "postSignatureResponse takes no bidirectional fields"],

  // ---- postRespondBidirectional ----
  ["serialized_output absent", bidirectional({ serialized_output: undefined }), "postRespondBidirectional needs serialized_output as 256 lowercase hex (Bytes<128>)"],
  ["serialized_output 254 hex", bidirectional({ serialized_output: "55".repeat(127) }), "postRespondBidirectional needs serialized_output as 256 lowercase hex (Bytes<128>)"],
  ["serialized_output uppercase", bidirectional({ serialized_output: "AA".repeat(128) }), "postRespondBidirectional needs serialized_output as 256 lowercase hex (Bytes<128>)"],
  ["output_len absent", bidirectional({ output_len: undefined }), "postRespondBidirectional output_len must be 0..=128"],
  ["output_len 129", bidirectional({ output_len: 129 }), "postRespondBidirectional output_len must be 0..=128"],
  ["output_len 255", bidirectional({ output_len: 255 }), "postRespondBidirectional output_len must be 0..=128"],

  // ---- circuit names ----
  ["an unrecognized circuit name", signatureResponse({ circuit: "postRespond" }), "unknown circuit postRespond"],
  ["empty circuit", signatureResponse({ circuit: "" }), "unknown circuit "],
  ["wrong case", signatureResponse({ circuit: "postsignatureresponse" }), "unknown circuit postsignatureresponse"],
  ["the notify circuit is not postable here", signatureResponse({ circuit: "signBidirectionalEvent" }), "unknown circuit signBidirectionalEvent"],
];

describe.each(REJECTIONS)("validateRespondRequest rejects %s", (_label, request, message) => {
  it(`with "${message}"`, () => {
    expect(() => validateRespondRequest(request)).toThrowError(message);
  });
});

describe("validateRespondRequest: checks fire in their pinned wire order", () => {
  it("reports the address before the request id", () => {
    expect(() => validateRespondRequest(signatureResponse({ contract_address: "nope", request_id: "nope" }))).toThrowError(
      "contract_address must be 64 lowercase hex",
    );
  });

  it("reports the request id before the circuit", () => {
    expect(() => validateRespondRequest(signatureResponse({ request_id: "nope", circuit: "nope" }))).toThrowError(
      "request_id must be 64 hex",
    );
  });

  it("reports a malformed scalar before a bad recovery id", () => {
    expect(() =>
      validateRespondRequest(
        signatureResponse({ signature: withSignature({ s: "zz".repeat(32), recovery_id: 9 }) }),
      ),
    ).toThrowError("signature.big_r.x, signature.big_r.y and signature.s must be 64 lowercase hex each");
  });

  it("reports the signature before the circuit's own fields", () => {
    // The signature is shared, so it is checked before the circuit splits.
    expect(() =>
      validateRespondRequest(
        bidirectional({ signature: withSignature({ s: "" }), serialized_output: "55" }),
      ),
    ).toThrowError("signature.big_r.x, signature.big_r.y and signature.s must be 64 lowercase hex each");
  });

  it("reports a bad serialized_output before a bad output_len", () => {
    expect(() => validateRespondRequest(bidirectional({ serialized_output: "55", output_len: 200 }))).toThrowError(
      "postRespondBidirectional needs serialized_output as 256 lowercase hex (Bytes<128>)",
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

const MISSING_FIELDS: [string, string][] = [
  ["contract_address", JSON.stringify({ ...bidirectional(), contract_address: undefined })],
  ["circuit", JSON.stringify({ ...bidirectional(), circuit: undefined })],
  ["request_id", JSON.stringify({ ...bidirectional(), request_id: undefined })],
  ["signature", JSON.stringify({ ...bidirectional(), signature: undefined })],
  ["signature.big_r", JSON.stringify({ ...bidirectional(), signature: { s: SIGNATURE.s, recovery_id: 1 } })],
  ["signature.big_r.x", JSON.stringify({ ...bidirectional(), signature: { ...SIGNATURE, big_r: { y: SIGNATURE.big_r.y } } })],
  ["signature.s", JSON.stringify({ ...bidirectional(), signature: { ...SIGNATURE, s: undefined } })],
  ["signature.recovery_id", JSON.stringify({ ...bidirectional(), signature: { ...SIGNATURE, recovery_id: undefined } })],
];

const WRONG_JSON_TYPES: [string, Record<string, unknown>, string][] = [
  ["contract_address as a number", { ...bidirectional(), contract_address: 1 }, "invalid JSON: `contract_address` must be a string"],
  ["signature as a string", { ...bidirectional(), signature: "nope" }, "invalid JSON: `signature` must be an object"],
  ["signature as an array", { ...bidirectional(), signature: [] }, "invalid JSON: `signature` must be an object"],
  ["big_r as a string", { ...bidirectional(), signature: { ...SIGNATURE, big_r: "nope" } }, "invalid JSON: `signature.big_r` must be an object"],
  ["big_r.x as a number", { ...bidirectional(), signature: { ...SIGNATURE, big_r: { x: 1, y: SIGNATURE.big_r.y } } }, "invalid JSON: `signature.big_r.x` must be a string"],
  ["output_len as a string", { ...bidirectional(), output_len: "64" }, "invalid JSON: `output_len` must be an integer in 0..=255"],
  ["output_len negative", { ...bidirectional(), output_len: -1 }, "invalid JSON: `output_len` must be an integer in 0..=255"],
  ["output_len fractional", { ...bidirectional(), output_len: 1.5 }, "invalid JSON: `output_len` must be an integer in 0..=255"],
  ["output_len beyond u8", { ...bidirectional(), output_len: 256 }, "invalid JSON: `output_len` must be an integer in 0..=255"],
  ["recovery_id as a string", { ...signatureResponse(), signature: { ...SIGNATURE, recovery_id: "1" } }, "invalid JSON: `signature.recovery_id` must be an integer in 0..=255"],
];

describe("parseRespondRequest", () => {
  // `toEqual`, not `toStrictEqual`: the parser materialises every optional
  // field as `undefined`, and an absent field and an `undefined` one are the
  // same thing in this contract, as the null-versus-absent case below pins.
  it("round-trips the postSignatureResponse body", () => {
    expect(parseRespondRequest(JSON.stringify(signatureResponse()))).toEqual(signatureResponse());
  });

  it("round-trips the postRespondBidirectional body", () => {
    expect(parseRespondRequest(JSON.stringify(bidirectional()))).toEqual(bidirectional());
  });

  it("treats null exactly as absent, matching serde's Option", () => {
    // A serde caller serializes the fields its circuit does not use as nulls;
    // rejecting those as contamination would reject every standard caller. The
    // nulled fields here are bidirectional-only — this body's own signature
    // (big_r_x/big_r_y/s/recovery_id) is present and stays required.
    const parsed = parseRespondRequest(
      JSON.stringify({ ...signatureResponse(), serialized_output: null, output_len: null }),
    );
    expect(parsed.serialized_output).toBeUndefined();
    expect(() => validateRespondRequest(parsed)).not.toThrow();
  });

  it("rejects a required signature field sent as null, since null is absent", () => {
    // The flip side of null-equals-absent: nulling a field the circuit NEEDS
    // is a missing signature, never a present-but-empty one.
    const body = JSON.stringify({ ...bidirectional(), signature: { ...SIGNATURE, s: null } });
    expect(() => parseRespondRequest(body)).toThrowError("invalid JSON: missing field `signature.s`");
  });

  it("ignores unknown fields, as the wire always has", () => {
    const body = JSON.stringify({ ...bidirectional(), output_hash: "deadbeef", extra: 1 });
    expect(() => validateRespondRequest(parseRespondRequest(body))).not.toThrow();
  });

  it.each(MALFORMED_BODIES)("rejects %s with an invalid-JSON message", (_label, body) => {
    expect(() => parseRespondRequest(body)).toThrowError(/^invalid JSON:/);
  });

  it.each(MISSING_FIELDS)("rejects a body missing %s", (field, body) => {
    expect(() => parseRespondRequest(body)).toThrowError(`invalid JSON: missing field \`${field}\``);
  });

  it.each(WRONG_JSON_TYPES)("rejects %s", (_label, body, message) => {
    expect(() => parseRespondRequest(JSON.stringify(body))).toThrowError(message);
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
    const request = signatureResponse();
    validateRespondRequest(request);
    const call = respondCall(request);

    expect(call.args).toHaveLength(2);
    expect(hex(call.args[0])).toBe(REQUEST_ID);
    const event = signatureEvent(request);
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
    const request = bidirectional();
    validateRespondRequest(request);
    const call = respondCall(request);

    expect(hex(call.args[0])).toBe(REQUEST_ID);
    const event = bidirectionalEvent(request);
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
    expect(() => validateRespondRequest(parseRespondRequest(body))).not.toThrow();
  });

  it("accepts the pinned postRespondBidirectional body byte for byte", () => {
    const body =
      `{"contract_address":"${ADDRESS}","circuit":"postRespondBidirectional","request_id":"${REQUEST_ID}",` +
      `"serialized_output":"${"55".repeat(128)}","output_len":64,` +
      `"signature":{"big_r":{"x":"${"22".repeat(32)}","y":"${"33".repeat(32)}"},"s":"${"44".repeat(32)}","recovery_id":0}}`;
    const request = parseRespondRequest(body);
    expect(() => validateRespondRequest(request)).not.toThrow();
    expect(request).toEqual(bidirectional());
  });

});

/** A node client that must never be reached: validation happens before any I/O. */
const forbiddenClient = new Proxy({} as NodeClient, {
  get(_target, property) {
    throw new Error(`no I/O may happen for an invalid request (touched ${String(property)})`);
  },
});

/** Endpoints that would fail loudly if the handler ever tried to use them. */
const offlineConfig: Config = {
  port: 0,
  bindHost: "127.0.0.1",
  nodeUrl: "ws://127.0.0.1:1",
  proofServerUrl: "http://127.0.0.1:1",
  indexerUrl: "http://127.0.0.1:1/api/v3/graphql",
  indexerWsUrl: "ws://127.0.0.1:1/api/v3/graphql/ws",
  managedDir: "/nonexistent",
  fundingSeed: `${"00".repeat(31)}01`,
  networkId: "undeployed",
};

const BAD_REQUESTS: [string, string, string | RegExp][] = [
  ["a malformed body", "{", /^invalid JSON:/],
  ["a bad address", JSON.stringify(bidirectional({ contract_address: "nope" })), "contract_address must be 64 lowercase hex"],
  ["an unknown circuit", JSON.stringify(signatureResponse({ circuit: "postRespond" })), "unknown circuit postRespond"],
  [
    "a contaminated body",
    JSON.stringify(signatureResponse({ serialized_output: "55".repeat(128) })),
    "postSignatureResponse takes no bidirectional fields",
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
    const reply = await handleRespond(offlineConfig, forbiddenClient, body);
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

/** The narrowing `validateRespondRequest` performs is what keeps `respondCall` total. */
describe("types", () => {
  it("narrows the circuit to the two postable ids", () => {
    const request = bidirectional();
    validateRespondRequest(request);
    const circuit: RespondCircuit = request.circuit;
    expect(circuit).toBe("postRespondBidirectional");
  });
});
