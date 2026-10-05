import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import {
  executedEvmRespondOutput,
  type EvmTraceOutput,
  EvmTraceOutputKind,
  respondOutputWidth,
} from "@sig-net/midnight-respond-oracle";
import { AbiCoder } from "ethers";

type OracleTrace =
  { kind: "NotTraced" } | { kind: "NoReturnData" } | { kind: "Output"; returnDataHex: string };

interface OracleVector {
  name: string;
  outputSchemaHex: string;
  isContractCall: boolean;
  trace: OracleTrace;
  expectedOutputHex?: string;
  expectedReject?: true;
}

interface OracleFixture {
  oracle: {
    midnightPackage: string;
    serializerPackage: string;
    ethers: string;
    sweepSeed: number;
  };
  vectors: OracleVector[];
}

interface Field {
  name: string;
  type: string;
}

interface Case {
  name: string;
  /** The on-chain schema bytes, NUL padding included. */
  schema: Uint8Array;
  isContractCall: boolean;
  trace: OracleTrace;
}

const coder = AbiCoder.defaultAbiCoder();

/**
 * `name@version` of an installed package. The oracle alias has no nested dependencies, so
 * it resolves the top-level serializer and ethers.
 */
const installedPackage = (directory: string): string => {
  const manifest = JSON.parse(
    readFileSync(new URL(`../node_modules/${directory}/package.json`, import.meta.url), "utf8"),
  ) as { name: string; version: string };
  return `${manifest.name}@${manifest.version}`;
};

const textEncoder = new TextEncoder();
const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(Buffer.from(value.replace(/^0x/, ""), "hex"));
const schemaBytes = (json: string): Uint8Array => textEncoder.encode(json);
const fieldsJson = (fields: readonly Field[]): string => JSON.stringify(fields);
const concat = (...parts: Uint8Array[]): Uint8Array => Uint8Array.from(Buffer.concat(parts));
const word = (lastByte: number): string => lastByte.toString(16).padStart(64, "0");
const output = (returnDataHex: string): OracleTrace => ({
  kind: "Output",
  returnDataHex: returnDataHex.replace(/^0x/, ""),
});
const encoded = (fields: readonly Field[], values: readonly unknown[]): OracleTrace =>
  output(
    coder.encode(
      fields.map((field) => field.type),
      values,
    ),
  );

const toOracleTrace = (trace: OracleTrace): EvmTraceOutput =>
  trace.kind === "Output"
    ? { kind: EvmTraceOutputKind.Output, returnData: fromHex(trace.returnDataHex) }
    : trace.kind === "NoReturnData"
      ? { kind: EvmTraceOutputKind.NoReturnData }
      : { kind: EvmTraceOutputKind.NotTraced };

const vectorFor = (input: Case): OracleVector => {
  const base = {
    name: input.name,
    outputSchemaHex: hex(input.schema),
    isContractCall: input.isContractCall,
    trace: input.trace,
  };
  let result: Uint8Array;
  try {
    result = executedEvmRespondOutput(
      input.schema,
      input.isContractCall,
      toOracleTrace(input.trace),
    );
  } catch {
    return { ...base, expectedReject: true };
  }
  if (result.length > 0 && result.length !== respondOutputWidth(input.schema)) {
    throw new Error(`${input.name}: output is not the schema's derived width`);
  }
  return { ...base, expectedOutputHex: hex(result) };
};

const nulPadded = (json: string, padding: number): Uint8Array =>
  concat(schemaBytes(json), new Uint8Array(padding));

const call = (
  name: string,
  json: string,
  trace: OracleTrace,
  schema: Uint8Array = schemaBytes(json),
): Case => ({ name, schema, isContractCall: true, trace });

const transfer = (name: string, json: string): Case => ({
  name,
  schema: schemaBytes(json),
  isContractCall: false,
  trace: { kind: "NotTraced" },
});

const BOOL: Field[] = [{ name: "ok", type: "bool" }];
const UINT: Field[] = [{ name: "amount", type: "uint256" }];
const ADDRESS: Field[] = [{ name: "to", type: "address" }];
const MIXED: Field[] = [
  { name: "ok", type: "bool" },
  { name: "amount", type: "uint256" },
  { name: "to", type: "address" },
  { name: "tag", type: "bytes4" },
  { name: "hash", type: "bytes32" },
];
const MIXED_VALUES = [
  true,
  0x0102030405060708090a0b0c0d0e0f10n,
  "0x8ba1f109551bd432803012645ac136ddd64dba72",
  "0xdeadbeef",
  `0x${"ab".repeat(32)}`,
];
const TAG_THEN_ADDRESS: Field[] = [
  { name: "tag", type: "bytes12" },
  { name: "to", type: "address" },
];

const handwritten: Case[] = [
  // Every supported type, its boundaries, and schema order.
  call("bool true", fieldsJson(BOOL), encoded(BOOL, [true])),
  call("bool false", fieldsJson(BOOL), encoded(BOOL, [false])),
  ...[0n, 1n, (1n << 128n) - 1n, 1n << 128n, 1n << 255n, (1n << 256n) - 1n].map((value) =>
    call(`uint256 ${value.toString()} is little-endian`, fieldsJson(UINT), encoded(UINT, [value])),
  ),
  call(
    "address keeps wire byte order",
    fieldsJson(ADDRESS),
    encoded(ADDRESS, ["0x0102030405060708090a0b0c0d0e0f1011121314"]),
  ),
  ...[1, 2, 16, 31, 32].map((length) => {
    const fields = [{ name: "value", type: `bytes${String(length)}` }];
    const value = `0x${Array.from({ length }, (_, index) => (index + 1).toString(16).padStart(2, "0")).join("")}`;
    return call(`bytes${String(length)} is verbatim`, fieldsJson(fields), encoded(fields, [value]));
  }),
  call("mixed fields keep schema order", fieldsJson(MIXED), encoded(MIXED, MIXED_VALUES)),
  call(
    "reversed mixed fields keep schema order",
    fieldsJson([...MIXED].reverse()),
    encoded([...MIXED].reverse(), [...MIXED_VALUES].reverse()),
  ),
  // Exactly fills the real-stack caller's 64-byte output schema field.
  call(
    "bytes12 then address keep schema order in a 64-byte schema",
    fieldsJson(TAG_THEN_ADDRESS),
    encoded(TAG_THEN_ADDRESS, [
      "0xa1a2a3a4a5a6a7a8a9aaabac",
      "0x0102030405060708090a0b0c0d0e0f1011121314",
    ]),
  ),

  // Field names: unique, non-empty Solidity identifiers other than __proto__.
  ...["$", "_", "a$1", "A_b9", "constructor", "toString", "uint256"].map((name) =>
    call(
      `identifier name '${name}' is accepted`,
      fieldsJson([{ name, type: "bool" }]),
      output(word(1)),
    ),
  ),
  ...["1", "0", "42", "1a", "a b", "a-b", "🌙", "é", "__proto__"].map((name) =>
    call(`name '${name}' is refused`, fieldsJson([{ name, type: "bool" }]), output(word(1))),
  ),
  call(
    "integer-like name after another field is refused",
    fieldsJson([
      { name: "b", type: "bool" },
      { name: "1", type: "uint256" },
    ]),
    output(word(1) + word(7)),
  ),
  call("missing name is refused", '[{"type":"bool"}]', output(word(1))),
  call("blank name is refused", '[{"name":"","type":"bool"}]', output(word(1))),
  call("non-string name is refused", '[{"name":1,"type":"bool"}]', output(word(1))),
  call(
    "duplicate field names are refused",
    fieldsJson([...BOOL, ...BOOL]),
    output(word(1) + word(1)),
  ),

  // Field types: matched on the raw string.
  call("missing type is refused", '[{"name":"ok"}]', output(word(1))),
  call("blank type is refused", '[{"name":"ok","type":""}]', output(word(1))),
  call("non-string type is refused", '[{"name":"ok","type":true}]', output(word(1))),
  ...[
    "uint",
    "uint8",
    "uint128",
    "int256",
    "string",
    "bytes",
    "bool[]",
    "bool[1]",
    "(bool)",
    "tuple",
    "address payable",
    "bytes0",
    "bytes33",
    "bytes01",
    "Bool",
    " bool",
    "bool ",
    "bool ok",
  ].map((type) =>
    // An all-zero word is canonical for every supported type, so only the type refuses it.
    call(`type '${type}' is refused`, fieldsJson([{ name: "x", type }]), output(word(0))),
  ),

  // Canonical schema bytes.
  call("canonical text without padding", fieldsJson(BOOL), encoded(BOOL, [true])),
  call("NUL padding after the text", "", encoded(BOOL, [true]), nulPadded(fieldsJson(BOOL), 4)),
  call(
    "a non-NUL byte after the first NUL is refused",
    "",
    encoded(BOOL, [true]),
    concat(schemaBytes(fieldsJson(BOOL)), Uint8Array.of(0, 0xde, 0xad)),
  ),
  call(
    "a leading BOM is refused",
    "",
    encoded(BOOL, [true]),
    concat(Uint8Array.of(0xef, 0xbb, 0xbf), schemaBytes(fieldsJson(BOOL))),
  ),
  call("whitespace is refused", ' [{"name":"ok","type":"bool"}]', encoded(BOOL, [true])),
  call("whitespace inside is refused", '[{"name": "ok","type":"bool"}]', encoded(BOOL, [true])),
  call("trailing newline is refused", `${fieldsJson(BOOL)}\n`, encoded(BOOL, [true])),
  call("type before name is refused", '[{"type":"bool","name":"ok"}]', encoded(BOOL, [true])),
  call(
    "extra keys are refused",
    '[{"name":"ok","type":"bool","internalType":"bool"}]',
    encoded(BOOL, [true]),
  ),
  call(
    "indexed key is refused",
    '[{"name":"ok","type":"bool","indexed":false}]',
    encoded(BOOL, [true]),
  ),
  call(
    "duplicate JSON keys are refused",
    '[{"name":"wrong","name":"ok","type":"bool"}]',
    encoded(BOOL, [true]),
  ),
  call(
    "escaped characters are refused",
    '[{"name":"\\u006fk","type":"bool"}]',
    encoded(BOOL, [true]),
  ),
  call(
    "invalid UTF-8 is refused",
    "",
    encoded(BOOL, [true]),
    concat(schemaBytes('[{"name":"a'), Uint8Array.of(0xff), schemaBytes('","type":"bool"}]')),
  ),
  call("non-JSON schema is refused", "not json", encoded(BOOL, [true])),
  call("JSON null schema is refused", "null", { kind: "NoReturnData" }),
  call("object schema is refused", '{"name":"ok","type":"bool"}', encoded(BOOL, [true])),
  call("null field is refused", "[null]", encoded(BOOL, [true])),
  call("array field is refused", '[["ok","bool"]]', encoded(BOOL, [true])),

  // Empty schemas.
  call("[] is the empty schema", "[]", { kind: "NoReturnData" }),
  call("[] with NUL padding is the empty schema", "", { kind: "NoReturnData" }, nulPadded("[]", 6)),
  call("no bytes is the empty schema", "", { kind: "NoReturnData" }),
  call("all-NUL bytes are the empty schema", "", { kind: "NoReturnData" }, new Uint8Array(8)),
  call("[ ] is refused", "[ ]", { kind: "NoReturnData" }),
  call("whitespace-only schema is refused", "  ", { kind: "NoReturnData" }),
  call("NEL-only schema is refused", "\u0085", { kind: "NoReturnData" }),
  call("NBSP-only schema is refused", "\u00a0", { kind: "NoReturnData" }),
  call(
    "a leading NUL followed by a non-NUL byte is refused",
    "",
    { kind: "NoReturnData" },
    concat(Uint8Array.of(0), schemaBytes("[]")),
  ),

  // Canonical return data.
  call("bool word 2 is refused", fieldsJson(BOOL), output(word(2))),
  call(
    "bool word with a high byte set is refused",
    fieldsJson(BOOL),
    output(`01${"00".repeat(31)}`),
  ),
  call(
    "bytes4 dirty right padding is refused",
    fieldsJson([{ name: "tag", type: "bytes4" }]),
    output(`12345678${"00".repeat(27)}01`),
  ),
  call(
    "bytes4 dirty only at the first padding byte is refused",
    fieldsJson([{ name: "tag", type: "bytes4" }]),
    output(`1234567801${"00".repeat(27)}`),
  ),
  call(
    "bytes32 uses the whole word",
    fieldsJson([{ name: "tag", type: "bytes32" }]),
    output("ff".repeat(32)),
  ),
  call(
    "dirty address padding is refused",
    fieldsJson(ADDRESS),
    output(`${"ff".repeat(12)}${"11".repeat(20)}`),
  ),
  call(
    "a single dirty address padding byte is refused",
    fieldsJson(ADDRESS),
    output(`01${"00".repeat(11)}${"11".repeat(20)}`),
  ),
  call(
    "an address dirty only at the last padding byte is refused",
    fieldsJson(ADDRESS),
    output(`${"00".repeat(11)}01${"11".repeat(20)}`),
  ),
  call("uint256 accepts any word", fieldsJson(UINT), output("ff".repeat(32))),
  call(
    "trailing words past the last field are ignored",
    fieldsJson(BOOL),
    output(word(1) + "ff".repeat(32)),
  ),
  call("a partial trailing word is refused", fieldsJson(BOOL), output(`${word(1)}ff`)),
  call("return data shorter than one word is refused", fieldsJson(BOOL), output("01")),
  call(
    "return data with fewer words than fields is refused",
    fieldsJson([...BOOL, ...UINT]),
    output(word(1)),
  ),

  // Empty outputs and schema/return-data mismatches.
  transfer("plain transfer with an empty schema attests an empty output", "[]"),
  transfer("plain transfer with no schema bytes attests an empty output", ""),
  transfer("plain transfer with a non-empty schema is refused", fieldsJson(BOOL)),
  transfer(
    "plain transfer with an unsupported type is refused",
    fieldsJson([{ name: "x", type: "uint8" }]),
  ),
  transfer("plain transfer with a non-canonical schema is refused", " []"),
  call("void call without return data attests an empty output", "[]", { kind: "NoReturnData" }),
  call("void call with empty return data attests an empty output", "[]", output("")),
  call("contract call without a trace is refused", "[]", { kind: "NotTraced" }),
  call("contract call with a schema but no return data is refused", fieldsJson(BOOL), {
    kind: "NoReturnData",
  }),
  call(
    "contract call with a schema but empty return data is refused",
    fieldsJson(BOOL),
    output(""),
  ),
  call("contract call returning data under an empty schema is refused", "[]", output(word(1))),
];

// Deterministic sweep over supported field mixes, schema padding and word-level corruptions.
const SWEEP_SEED = 0x5eed_0b05;
const SWEEP_CASES = 400;

const mulberry32 = (seed: number): (() => number) => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let mixed = Math.imul(state ^ (state >>> 15), state | 1);
    mixed ^= mixed + Math.imul(mixed ^ (mixed >>> 7), mixed | 61);
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
};
const random = mulberry32(SWEEP_SEED);
const randomInt = (bound: number): number => Math.floor(random() * bound);
const randomBytes = (length: number): Uint8Array =>
  Uint8Array.from({ length }, () => randomInt(256));
const pick = <T>(items: readonly T[]): T => {
  const item = items[randomInt(items.length)];
  if (item === undefined) throw new Error("pick from an empty list");
  return item;
};
const UINT_BOUNDARIES = [0n, 1n, (1n << 128n) - 1n, 1n << 128n, (1n << 256n) - 1n];

const randomField = (index: number): { field: Field; value: unknown } => {
  const name = `f${String(index)}`;
  switch (randomInt(4)) {
    case 0:
      return { field: { name, type: "bool" }, value: random() < 0.5 };
    case 1:
      return {
        field: { name, type: "uint256" },
        value: random() < 0.5 ? pick(UINT_BOUNDARIES) : BigInt(`0x${hex(randomBytes(32))}`),
      };
    case 2:
      return { field: { name, type: "address" }, value: `0x${hex(randomBytes(20))}` };
    default: {
      const length = 1 + randomInt(32);
      return {
        field: { name, type: `bytes${String(length)}` },
        value: `0x${hex(randomBytes(length))}`,
      };
    }
  }
};

const corrupt = (
  fields: readonly Field[],
  data: Uint8Array,
): { label: string; data: Uint8Array } => {
  const copy = Uint8Array.from(data);
  const index = randomInt(fields.length);
  const field = fields[index];
  if (field === undefined) throw new Error("corrupt an empty field list");
  const start = index * 32;
  switch (randomInt(6)) {
    case 0: {
      // Dirty the bytes a canonical word keeps zero (any byte for uint256).
      const position =
        field.type === "address" || field.type === "bool"
          ? start + randomInt(field.type === "address" ? 12 : 31)
          : field.type.startsWith("bytes") && field.type !== "bytes32"
            ? start + Number(field.type.slice(5)) + randomInt(32 - Number(field.type.slice(5)))
            : start + randomInt(32);
      copy[position] = 1 + randomInt(255);
      return { label: `dirty word ${String(index)}`, data: copy };
    }
    case 1:
      return { label: "truncated", data: copy.subarray(0, randomInt(copy.length)) };
    case 2:
      return { label: "trailing bytes", data: concat(copy, randomBytes(1 + randomInt(40))) };
    case 3:
      return { label: "trailing words", data: concat(copy, randomBytes(32 * (1 + randomInt(3)))) };
    case 4:
      return { label: "empty", data: new Uint8Array(0) };
    default:
      return { label: "clean", data: copy };
  }
};

const sweep: Case[] = Array.from({ length: SWEEP_CASES }, (_, caseIndex) => {
  const generated = Array.from({ length: 1 + randomInt(6) }, (_, index) => randomField(index));
  const fields = generated.map((entry) => entry.field);
  const data = fromHex(
    coder.encode(
      fields.map((field) => field.type),
      generated.map((entry) => entry.value),
    ),
  );
  const variant = caseIndex % 3 === 0 ? { label: "clean", data } : corrupt(fields, data);
  const padding = randomInt(9);
  return call(
    `sweep ${String(caseIndex)}: ${fields.map((field) => field.type).join(",")} (${variant.label}, ${String(padding)} NUL)`,
    "",
    output(hex(variant.data)),
    nulPadded(fieldsJson(fields), padding),
  );
});

const vectors = [...handwritten, ...sweep].map(vectorFor);

const accepted = vectors.filter((vector) => vector.expectedReject !== true).length;
if (accepted === 0 || accepted === vectors.length) {
  throw new Error("oracle fixture must contain both accepted and refused vectors");
}

const fixture: OracleFixture = {
  oracle: {
    midnightPackage: installedPackage("@sig-net/midnight-respond-oracle"),
    serializerPackage: installedPackage("@sig-net/midnight-serde"),
    ethers: installedPackage("ethers"),
    sweepSeed: SWEEP_SEED,
  },
  vectors,
};

const fixtureDirectory = new URL("../../chain-ethereum/tests/fixtures/", import.meta.url);
const fixturePath = new URL("midnight_respond_vectors.json", fixtureDirectory);
mkdirSync(fixtureDirectory, { recursive: true });
writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(
  `wrote ${String(vectors.length)} Midnight respond oracle vectors (${String(accepted)} accepted)`,
);
