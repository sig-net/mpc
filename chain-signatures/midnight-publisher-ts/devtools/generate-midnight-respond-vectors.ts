import { mkdirSync, writeFileSync } from "node:fs";
import { FIELD_MODULUS } from "@midnight-ntwrk/compact-runtime";
import {
  deserializeEvmOutput,
  MAX_RESPOND_PACKED_BYTES,
  serializeRespondOutput,
} from "@sig-net/midnight";
import { AbiCoder } from "ethers";

interface OracleVector {
  name: string;
  outputSchemaHex: string;
  respondSchemaHex: string;
  callResultHex: string;
  expectedOutputHex?: string;
  expectedReject?: true;
}

interface OracleFixture {
  oracle: {
    fakenetCommit: "7084242437d8a0e52f3648f4a3594f9dd401ef71";
    midnightIntegrationCommit: "c171225731f5ca07028fcd6caa6ced853ed139ef";
    midnightPackage: "@sig-net/midnight@0.20.0-rc.1";
    serializerPackage: "@sig-net/midnight-serde@0.20.0-rc.1";
    ethers: "6.17.0";
  };
  vectors: OracleVector[];
}

interface EvmField {
  name: string;
  type: string;
  maxBytes?: unknown;
  maxItems?: unknown;
}

interface VectorInput {
  name: string;
  outputSchema: readonly EvmField[];
  outputSchemaJson?: string;
  respondSchema: unknown;
  respondSchemaJson?: string;
  values: readonly unknown[];
  callResultHex?: string;
  padding?: SchemaPadding;
  utf8Bom?: boolean;
  assertRejection?: (error: unknown) => void;
}

interface ValidVectorInput extends VectorInput {
  expectedOutputLength?: number;
}

type SchemaPadding = "trailing-nuls" | "nonzero-after-first-nul";

const coder = AbiCoder.defaultAbiCoder();
const textEncoder = new TextEncoder();

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const stripHexPrefix = (value: string): string => value.slice(2);

const onchainSchemaJson = (
  schemaJson: string,
  padding: SchemaPadding = "trailing-nuls",
  utf8Bom = false,
): Uint8Array => {
  const json = textEncoder.encode(schemaJson);
  const prefix = utf8Bom ? Uint8Array.of(0xef, 0xbb, 0xbf) : new Uint8Array();
  const suffix =
    padding === "trailing-nuls"
      ? Uint8Array.of(0, 0, 0, 0)
      : Uint8Array.of(0, 0xde, 0xad, 0xbe, 0xef);
  const padded = new Uint8Array(prefix.length + json.length + suffix.length);
  padded.set(prefix);
  padded.set(json, prefix.length);
  padded.set(suffix, prefix.length + json.length);
  return padded;
};

const onchainSchema = (schema: unknown, padding?: SchemaPadding, utf8Bom?: boolean): Uint8Array =>
  onchainSchemaJson(JSON.stringify(schema), padding, utf8Bom);

const forwardedSchema = (schema: Uint8Array): Uint8Array => {
  const firstNul = schema.indexOf(0);
  return firstNul === -1 ? schema : schema.subarray(0, firstNul);
};

const baseVector = (
  input: VectorInput,
  respondSchema: Uint8Array,
  callResult: string,
): OracleVector => ({
  name: input.name,
  outputSchemaHex: hex(textEncoder.encode(JSON.stringify(input.outputSchema))),
  respondSchemaHex: hex(forwardedSchema(respondSchema)),
  callResultHex: stripHexPrefix(callResult),
});

const validVector = (input: ValidVectorInput): OracleVector => {
  const outputSchema =
    input.outputSchemaJson === undefined
      ? onchainSchema(input.outputSchema, input.padding, input.utf8Bom)
      : onchainSchemaJson(input.outputSchemaJson, input.padding, input.utf8Bom);
  const respondSchema =
    input.respondSchemaJson === undefined
      ? onchainSchema(input.respondSchema, input.padding, input.utf8Bom)
      : onchainSchemaJson(input.respondSchemaJson, input.padding, input.utf8Bom);
  const callResult =
    input.callResultHex ??
    coder.encode(
      input.outputSchema.map((field) => field.type),
      input.values,
    );
  const decoded = deserializeEvmOutput(outputSchema, callResult);
  const output = serializeRespondOutput(respondSchema, decoded);
  if (input.expectedOutputLength !== undefined && output.length !== input.expectedOutputLength) {
    throw new Error(
      `${input.name}: expected ${String(input.expectedOutputLength)} output bytes, got ${String(output.length)}`,
    );
  }
  return {
    ...baseVector(input, respondSchema, callResult),
    expectedOutputHex: hex(output),
  };
};

const rejectedVector = (input: VectorInput): OracleVector => {
  const outputSchema =
    input.outputSchemaJson === undefined
      ? onchainSchema(input.outputSchema, input.padding, input.utf8Bom)
      : onchainSchemaJson(input.outputSchemaJson, input.padding, input.utf8Bom);
  const respondSchema =
    input.respondSchemaJson === undefined
      ? onchainSchema(input.respondSchema, input.padding, input.utf8Bom)
      : onchainSchemaJson(input.respondSchemaJson, input.padding, input.utf8Bom);
  const callResult =
    input.callResultHex ??
    coder.encode(
      input.outputSchema.map((field) => field.type),
      input.values,
    );
  let rejected = false;
  try {
    const decoded = deserializeEvmOutput(outputSchema, callResult);
    serializeRespondOutput(respondSchema, decoded);
  } catch (error) {
    input.assertRejection?.(error);
    rejected = true;
  }
  if (!rejected) {
    throw new Error(`oracle unexpectedly accepted rejection vector: ${input.name}`);
  }
  return {
    ...baseVector(input, respondSchema, callResult),
    expectedReject: true,
  };
};

const DYNAMIC_LENGTH_PREFIX_BYTES = 8;
const maxBytesAtPackedCeiling = MAX_RESPOND_PACKED_BYTES - DYNAMIC_LENGTH_PREFIX_BYTES;
const packedWidthAboveCeiling = MAX_RESPOND_PACKED_BYTES + 1;
const maxBytesAbovePackedCeiling = packedWidthAboveCeiling - DYNAMIC_LENGTH_PREFIX_BYTES;

const assertPackedWidthCeilingRejection = (error: unknown): void => {
  const expectedMessage =
    `respond schema packs to ${String(packedWidthAboveCeiling)} bytes, above the ` +
    `${String(MAX_RESPOND_PACKED_BYTES)}-byte ceiling`;
  if (!(error instanceof Error) || error.message !== expectedMessage) {
    throw new Error("oracle rejection was not the expected packed-width ceiling rejection", {
      cause: error,
    });
  }
};

const validInputs: ValidVectorInput[] = [
  {
    name: "bool true with trailing NUL schema padding",
    outputSchema: [{ name: "success", type: "bool" }],
    respondSchema: [{ name: "success", type: "bool" }],
    values: [true],
  },
  {
    name: "bool false ignores nonzero bytes after first NUL",
    outputSchema: [{ name: "success", type: "bool" }],
    respondSchema: [{ name: "success", type: "bool" }],
    values: [false],
    padding: "nonzero-after-first-nul",
  },
  {
    name: "raw schema bytes strip one leading UTF-8 BOM",
    outputSchema: [{ name: "success", type: "bool" }],
    respondSchema: [{ name: "success", type: "bool" }],
    values: [true],
    utf8Bom: true,
  },
  {
    name: "duplicate schema properties use the last JSON value",
    outputSchema: [{ name: "message", type: "string" }],
    outputSchemaJson:
      `[{"name":"wrong","name":"message","type":"bool","type":"string",` +
      `"maxBytes":1,"maxBytes":2}]`,
    respondSchema: null,
    respondSchemaJson:
      `[{"name":"wrong","name":"message","type":"bytes","type":"string",` +
      `"maxBytes":1,"maxBytes":2}]`,
    values: ["xy"],
  },
  {
    name: "uint256 decode narrows to uint128 response",
    outputSchema: [{ name: "amount", type: "uint256" }],
    respondSchema: [{ name: "amount", type: "uint128" }],
    values: [0x0102030405060708n],
  },
  {
    name: "uint256 response uses little-endian Field carrier",
    outputSchema: [{ name: "value", type: "uint256" }],
    respondSchema: [{ name: "value", type: "uint256" }],
    values: [0x0102030405060708n],
  },
  {
    name: "field response uses little-endian Field carrier",
    outputSchema: [{ name: "value", type: "uint256" }],
    respondSchema: [{ name: "value", type: "field" }],
    values: [0x0102030405060708n],
  },
  {
    name: "address response uses little-endian numeric carrier",
    outputSchema: [{ name: "to", type: "address" }],
    respondSchema: [{ name: "to", type: "address" }],
    values: ["0x0000000000000000000000000000000000000102"],
  },
  {
    name: "address decoded as a string retains ethers checksum casing",
    outputSchema: [{ name: "to", type: "address" }],
    respondSchema: [{ name: "to", type: "string", maxBytes: 42 }],
    values: ["0x8ba1f109551bd432803012645ac136ddd64dba72"],
  },
  {
    name: "numeric string coercion follows JavaScript BigInt grammar",
    outputSchema: [
      { name: "plus", type: "string" },
      { name: "upperHex", type: "string" },
      { name: "spaced", type: "string" },
      { name: "empty", type: "string" },
      { name: "blank", type: "string" },
      { name: "binary", type: "string" },
      { name: "octal", type: "string" },
      { name: "negativeZero", type: "string" },
    ],
    respondSchema: [
      { name: "plus", type: "uint8" },
      { name: "upperHex", type: "uint8" },
      { name: "spaced", type: "uint8" },
      { name: "empty", type: "uint8" },
      { name: "blank", type: "uint8" },
      { name: "binary", type: "uint8" },
      { name: "octal", type: "uint8" },
      { name: "negativeZero", type: "uint8" },
    ],
    values: ["+123", "0X7B", " 123 ", "", " ", "0b101", "0o77", "-0"],
  },
  {
    name: "numeric string coercion trims ECMAScript BOM whitespace",
    outputSchema: [{ name: "value", type: "string" }],
    respondSchema: [{ name: "value", type: "uint8" }],
    values: ["\uFEFF123\uFEFF"],
  },
  {
    name: "uppercase hex prefix is accepted for bytes coercion",
    outputSchema: [{ name: "tag", type: "string" }],
    respondSchema: [{ name: "tag", type: "bytes1" }],
    values: ["0X12"],
  },
  {
    name: "irrelevant malformed capacities are ignored for fixed carriers",
    outputSchema: [{ name: "ok", type: "bool", maxBytes: "ignored", maxItems: -1 }],
    respondSchema: [{ name: "ok", type: "bool", maxBytes: "ignored", maxItems: 1.5 }],
    values: [false],
  },
  {
    name: "irrelevant out-of-range capacity numbers are ignored for fixed carriers",
    outputSchema: [{ name: "ok", type: "bool" }],
    respondSchema: null,
    respondSchemaJson: `[{"name":"ok","type":"bool","maxBytes":1e400}]`,
    values: [true],
  },
  {
    name: "bytes4 response is verbatim",
    outputSchema: [{ name: "selector", type: "bytes4" }],
    respondSchema: [{ name: "selector", type: "bytes4" }],
    values: ["0xdeadbeef"],
  },
  {
    name: "bytes32 response is verbatim",
    outputSchema: [{ name: "hash", type: "bytes32" }],
    respondSchema: [{ name: "hash", type: "bytes32" }],
    values: [`0x${"ab".repeat(32)}`],
  },
  {
    name: "UTF-8 string uses byte length and maxBytes capacity",
    outputSchema: [{ name: "message", type: "string" }],
    respondSchema: [{ name: "message", type: "string", maxBytes: 24 }],
    values: ["Midnight 🌙"],
  },
  {
    name: "dynamic bytes use length and maxBytes capacity",
    outputSchema: [{ name: "payload", type: "bytes" }],
    respondSchema: [{ name: "payload", type: "bytes", maxBytes: 8 }],
    values: ["0xdeadbeef00"],
  },
  {
    name: "dynamic ABI array maps into fixed-capacity response array",
    outputSchema: [{ name: "values", type: "uint64[]" }],
    respondSchema: [{ name: "values", type: "uint64[]", maxItems: 3 }],
    values: [[7n, 8n]],
  },
  {
    name: "fixed ABI array maps into fixed-capacity response array",
    outputSchema: [{ name: "selectors", type: "bytes4[2]" }],
    respondSchema: [{ name: "selectors", type: "bytes4[]", maxItems: 3 }],
    values: [["0xdeadbeef", "0xcafebabe"]],
  },
  {
    name: "response fields can reorder and subset decoded values",
    outputSchema: [
      { name: "amount", type: "uint256" },
      { name: "ignoredDelta", type: "int256" },
      { name: "ok", type: "bool" },
    ],
    respondSchema: [
      { name: "ok", type: "bool" },
      { name: "amount", type: "uint128" },
    ],
    values: [4242n, -5n, true],
  },
  {
    name: "multiple response fields retain declaration order",
    outputSchema: [
      { name: "ok", type: "bool" },
      { name: "amount", type: "uint256" },
      { name: "tag", type: "bytes4" },
    ],
    respondSchema: [
      { name: "ok", type: "bool" },
      { name: "amount", type: "uint128" },
      { name: "tag", type: "bytes4" },
    ],
    values: [true, 123456789n, "0xcafebabe"],
  },
  {
    name: "packed response exactly at 65536-byte ceiling",
    outputSchema: [{ name: "blob", type: "bytes" }],
    respondSchema: [{ name: "blob", type: "bytes", maxBytes: maxBytesAtPackedCeiling }],
    values: ["0x01"],
    expectedOutputLength: MAX_RESPOND_PACKED_BYTES,
  },
];

const rejectionInputs: VectorInput[] = [
  {
    name: "reject empty response schema",
    outputSchema: [{ name: "ok", type: "bool" }],
    respondSchema: [],
    values: [true],
  },
  {
    name: "reject non-array response schema",
    outputSchema: [{ name: "ok", type: "bool" }],
    respondSchema: { name: "ok", type: "bool" },
    values: [true],
  },
  {
    name: "reject duplicate response field names",
    outputSchema: [{ name: "value", type: "uint256" }],
    respondSchema: [
      { name: "value", type: "uint128" },
      { name: "value", type: "uint128" },
    ],
    values: [1n],
  },
  {
    name: "reject __proto__ response field name",
    outputSchema: [{ name: "__proto__", type: "bool" }],
    respondSchema: [{ name: "__proto__", type: "bool" }],
    values: [true],
  },
  {
    name: "reject signed response type",
    outputSchema: [{ name: "delta", type: "int64" }],
    respondSchema: [{ name: "delta", type: "int64" }],
    values: [-1n],
  },
  {
    name: "reject non-whole-byte uint width",
    outputSchema: [{ name: "value", type: "uint256" }],
    respondSchema: [{ name: "value", type: "uint7" }],
    values: [1n],
  },
  {
    name: "reject uint width between 249 and 255",
    outputSchema: [{ name: "value", type: "uint256" }],
    respondSchema: [{ name: "value", type: "uint250" }],
    values: [1n],
  },
  {
    name: "reject bytes width above 32",
    outputSchema: [{ name: "value", type: "bytes32" }],
    respondSchema: [{ name: "value", type: "bytes33" }],
    values: [`0x${"01".repeat(32)}`],
  },
  {
    name: "reject missing maxBytes capacity",
    outputSchema: [{ name: "message", type: "string" }],
    respondSchema: [{ name: "message", type: "string" }],
    values: ["x"],
  },
  {
    name: "reject missing maxItems capacity",
    outputSchema: [{ name: "values", type: "uint64[]" }],
    respondSchema: [{ name: "values", type: "uint64[]" }],
    values: [[1n]],
  },
  {
    name: "reject nonpositive maxBytes capacity",
    outputSchema: [{ name: "payload", type: "bytes" }],
    respondSchema: [{ name: "payload", type: "bytes", maxBytes: 0 }],
    values: ["0x01"],
  },
  {
    name: "reject fractional maxItems capacity",
    outputSchema: [{ name: "values", type: "uint64[]" }],
    respondSchema: [{ name: "values", type: "uint64[]", maxItems: 1.5 }],
    values: [[1n]],
  },
  {
    name: "reject out-of-range maxBytes when capacity is required",
    outputSchema: [{ name: "value", type: "bytes" }],
    respondSchema: null,
    respondSchemaJson: `[{"name":"value","type":"bytes","maxBytes":1e400}]`,
    values: ["0x01"],
  },
  {
    name: "reject response field missing from decoded values",
    outputSchema: [{ name: "present", type: "bool" }],
    respondSchema: [{ name: "missing", type: "bool" }],
    values: [true],
  },
  {
    name: "reject empty dynamic bytes coerced to an integer",
    outputSchema: [{ name: "value", type: "bytes" }],
    respondSchema: [{ name: "value", type: "uint128" }],
    values: ["0x"],
  },
  {
    name: "reject non-ECMAScript U+0085 around numeric text",
    outputSchema: [{ name: "value", type: "string" }],
    respondSchema: [{ name: "value", type: "uint8" }],
    values: ["\u0085123\u0085"],
  },
  {
    name: "reject underscore separator in numeric text",
    outputSchema: [{ name: "value", type: "string" }],
    respondSchema: [{ name: "value", type: "uint8" }],
    values: ["1_0"],
  },
  {
    name: "reject dynamic payload above maxBytes",
    outputSchema: [{ name: "message", type: "string" }],
    respondSchema: [{ name: "message", type: "string", maxBytes: 5 }],
    values: ["ééé"],
  },
  {
    name: "reject dynamic array above maxItems",
    outputSchema: [{ name: "values", type: "uint64[]" }],
    respondSchema: [{ name: "values", type: "uint64[]", maxItems: 1 }],
    values: [[1n, 2n]],
  },
  {
    name: "reject value at Field modulus",
    outputSchema: [{ name: "value", type: "uint256" }],
    respondSchema: [{ name: "value", type: "field" }],
    values: [FIELD_MODULUS],
  },
  {
    name: "reject address at 2^160 decoded through uint256 producer",
    outputSchema: [{ name: "to", type: "uint256" }],
    respondSchema: [{ name: "to", type: "address" }],
    values: [1n << 160n],
  },
  {
    name: "reject packed response width of 65537 bytes",
    outputSchema: [{ name: "blob", type: "bytes" }],
    respondSchema: [{ name: "blob", type: "bytes", maxBytes: maxBytesAbovePackedCeiling }],
    values: ["0x01"],
    assertRejection: assertPackedWidthCeilingRejection,
  },
];

const vectors = [...validInputs.map(validVector), ...rejectionInputs.map(rejectedVector)];

const fixture: OracleFixture = {
  oracle: {
    fakenetCommit: "7084242437d8a0e52f3648f4a3594f9dd401ef71",
    midnightIntegrationCommit: "c171225731f5ca07028fcd6caa6ced853ed139ef",
    midnightPackage: "@sig-net/midnight@0.20.0-rc.1",
    serializerPackage: "@sig-net/midnight-serde@0.20.0-rc.1",
    ethers: "6.17.0",
  },
  vectors,
};

if (fixture.vectors.length === 0) {
  throw new Error("oracle fixture must contain vectors");
}

const fixtureDirectory = new URL("../../chain-ethereum/tests/fixtures/", import.meta.url);
const fixturePath = new URL("midnight_respond_vectors.json", fixtureDirectory);
mkdirSync(fixtureDirectory, { recursive: true });
writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(`wrote ${fixture.vectors.length} Midnight respond oracle vectors`);
