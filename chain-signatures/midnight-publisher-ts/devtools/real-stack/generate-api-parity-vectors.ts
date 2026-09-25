import { writeFileSync } from "node:fs";
import assert from "node:assert/strict";
import { createCircuitContext, createConstructorContext } from "@midnight-ntwrk/compact-runtime";
import { SigningKey, getBytes } from "ethers";
import {
  calculateRequestId,
  calculateEvmType2TxParamsDigest,
  decodeSignetLogEvents,
  decodeRespondBidirectionalEventPayload,
} from "@sig-net/midnight";
import { calculateSignetAttestationDigest } from "@sig-net/midnight/testing";
import { Contract as SingletonContract } from "@sig-net/midnight-contract";
import { Contract, pureCircuits } from "./managed/api-parity-oracle/contract/index.js";

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const padded = (text: string, width: number): Uint8Array => {
  const bytes = new Uint8Array(width);
  bytes.set(new TextEncoder().encode(text));
  return bytes;
};

const record: Parameters<typeof pureCircuits.requestId34>[0] = {
  keyVersion: 1n,
  sender: { bytes: new Uint8Array(32).fill(0xab) },
  path: padded("caller-path", 32),
  algo: 0,
  txParamType: 0,
  txParams: {
    chainId: 31337n,
    nonce: 3n,
    maxPriorityFeePerGas: 1n,
    maxFeePerGas: 2n,
    gasLimit: 21000n,
    to: new Uint8Array(20).fill(0xcd),
    value: 5n,
    calldata: {
      is_some: true,
      value: {
        selector: Uint8Array.of(0xca, 0x11, 0xab, 0x1e),
        noWords: 1n,
        words: [new Uint8Array(32).fill(0x11)],
      },
    },
    accessListEntryCount: 0n,
    accessList: [],
  },
  executionDest: padded("eip155:31337", 32),
  signatureDest: 0,
  params: new Uint8Array(64),
  outputDeserializationSchema: padded("uint256", 34),
  respondSerializationSchema: padded("uint256", 34),
};
const requestId = pureCircuits.requestId34(record);
assert.deepEqual(requestId, calculateRequestId(record));
assert.deepEqual(
  pureCircuits.requestId34({
    ...record,
    signatureDest: 1,
    params: new Uint8Array(64).fill(7),
    outputDeserializationSchema: padded("different-output-schema", 34),
    respondSerializationSchema: padded("different-response-schema", 34),
  }),
  requestId,
);
const minimal: Parameters<typeof pureCircuits.requestId000>[0] = {
  ...record,
  txParams: {
    ...record.txParams,
    calldata: { is_some: false, value: { selector: new Uint8Array(4), noWords: 0n, words: [] } },
  },
};
const unused: Parameters<typeof pureCircuits.requestId122>[0] = {
  ...record,
  txParams: {
    ...record.txParams,
    accessList: [0, 1].map(() => ({
      address: new Uint8Array(20),
      storageKeyCount: 0n,
      storageKeys: [new Uint8Array(32), new Uint8Array(32)],
    })),
  },
};
const partial: Parameters<typeof pureCircuits.requestId223>[0] = {
  ...record,
  txParams: {
    ...record.txParams,
    calldata: {
      is_some: true,
      value: {
        ...record.txParams.calldata.value,
        noWords: 2n,
        words: [new Uint8Array(32).fill(0x11), new Uint8Array(32).fill(0x22)],
      },
    },
    accessListEntryCount: 1n,
    accessList: [
      {
        address: new Uint8Array(20).fill(0xef),
        storageKeyCount: 3n,
        storageKeys: [1, 2, 3].map((byte) => new Uint8Array(32).fill(byte)),
      },
      {
        address: new Uint8Array(20),
        storageKeyCount: 0n,
        storageKeys: [0, 0, 0].map(() => new Uint8Array(32)),
      },
    ],
  },
};
type Records = [typeof record, typeof minimal, typeof unused, typeof partial];
const defaults: Records = [record, minimal, unused, partial];
async function requestVector(name: string, index: 0 | 1 | 2 | 3, records = defaults) {
  const ids = [
    pureCircuits.requestId34(records[0]),
    pureCircuits.requestId000(records[1]),
    pureCircuits.requestId122(records[2]),
    pureCircuits.requestId223(records[3]),
  ];
  const digests = [
    pureCircuits.txParamsDigest34(records[0].txParams),
    pureCircuits.txParamsDigest000(records[1].txParams),
    pureCircuits.txParamsDigest122(records[2].txParams),
    pureCircuits.txParamsDigest223(records[3].txParams),
  ];
  assert.deepEqual(ids[index], calculateRequestId(records[index]));
  assert.deepEqual(digests[index], calculateEvmType2TxParamsDigest(records[index].txParams));
  const { currentContractState } = await new Contract({}).initialState(
    createConstructorContext({}, "44".repeat(32)),
    ...records,
  );
  const cell = currentContractState.data.state.asArray()?.[index]?.asCell();
  assert.ok(cell);
  return {
    name,
    requestId: hex(ids[index]!),
    txParamsDigest: hex(digests[index]!),
    atoms: cell.value.map(hex),
    widths: cell.alignment.map((segment) => {
      assert.ok(segment.tag === "atom" && segment.value.tag === "bytes");
      return segment.value.length;
    }),
  };
}
const requestVectors = await Promise.all([
  requestVector("sample", 0),
  requestVector("minimal", 1),
  requestVector("unused-access-list", 2),
  requestVector("partial-access-list", 3),
]);
for (const [name, modify] of [
  [
    "unused-slots",
    (value) => {
      value.txParams.calldata.value.noWords = 1n;
      value.txParams.calldata.value.words[1]!.fill(0xfa);
      value.txParams.accessList[0]!.storageKeyCount = 1n;
      value.txParams.accessList[0]!.storageKeys[1]!.fill(0xfb);
      value.txParams.accessList[0]!.storageKeys[2]!.fill(0xfc);
      value.txParams.accessList[1]!.address.fill(0xfd);
      value.txParams.accessList[1]!.storageKeyCount = 3n;
      for (const key of value.txParams.accessList[1]!.storageKeys) key.fill(0xfe);
    },
  ],
  [
    "absent-calldata",
    (value) => {
      value.txParams.calldata.is_some = false;
    },
  ],
  [
    "empty-calldata",
    (value) => {
      value.txParams.calldata.value.noWords = 0n;
    },
  ],
  [
    "full-access-list",
    (value) => {
      value.txParams.accessListEntryCount = 2n;
    },
  ],
  [
    "integer-boundaries",
    (value) => {
      value.keyVersion = 255n;
      value.txParams.chainId = 0xffffffffffffffffn;
      value.txParams.nonce = 0xffffffffffffffffn;
      value.txParams.gasLimit = 0xffffffffffffffffn;
      value.txParams.maxPriorityFeePerGas = 0xffffffffffffffffffffffffffffffffn;
      value.txParams.maxFeePerGas = 0xffffffffffffffffffffffffffffffffn;
      value.txParams.value = 0xffffffffffffffffffffffffffffffffn;
    },
  ],
] satisfies [string, (value: typeof partial) => void][]) {
  const records = structuredClone(defaults);
  modify(records[3]);
  requestVectors.push(await requestVector(name, 3, records));
}
assert.equal(requestVectors[0]!.requestId, requestVectors[2]!.requestId);

const rid = new Uint8Array(32).fill(0x2f);
const data = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const digests: ReadonlyMap<number, typeof pureCircuits.digest0> = new Map([
  [0, pureCircuits.digest0],
  [1, pureCircuits.digest1],
  [30, pureCircuits.digest30],
  [31, pureCircuits.digest31],
  [32, pureCircuits.digest32],
  [62, pureCircuits.digest62],
  [63, pureCircuits.digest63],
]);
const inputs = [
  ...[0, 1, 30, 31, 32, 62, 63].map((width) => ({
    keyVersion: 1n,
    kind: 0 as const,
    blockHeight: 42n,
    data: Uint8Array.from({ length: width }, (_, index) => index + 1),
  })),
  ...[1, 2].map((kind) => ({ keyVersion: 1n, kind, blockHeight: 42n, data: new Uint8Array() })),
  {
    keyVersion: 0xfedcba98n,
    kind: 0 as const,
    blockHeight: 0xfedcba9876543210n,
    data: new Uint8Array(63).fill(0xa5),
  },
];
const vectors = inputs.map((input) => {
  const digestFunction = digests.get(input.data.length);
  assert.ok(digestFunction);
  const cache = input.data;
  const digest = digestFunction(rid, input.blockHeight, input.kind, input.data);
  assert.deepEqual(
    digest,
    calculateSignetAttestationDigest(rid, input.blockHeight, input.kind, input.data),
  );
  return {
    ...input,
    digest,
    cache,
  };
});
assert.throws(() => pureCircuits.digest0(rid, 42n, 3, new Uint8Array()));
const signingKey = new SigningKey(new Uint8Array(32).fill(7));
const signedResponse = (
  kind: 0 | 1 | 2,
  data: Uint8Array,
): Parameters<typeof pureCircuits.verify32>[1] => {
  const digest = calculateSignetAttestationDigest(rid, 42n, kind, data);
  const signature = signingKey.sign(digest);
  const noncePoint = getBytes(
    SigningKey.computePublicKey(`0x0${2 + signature.yParity}${signature.r.slice(2)}`, false),
  );
  return {
    requestId: rid,
    blockHeight: 42n,
    outputKind: kind,
    serializedOutputLength: BigInt(data.length),
    digest,
    signature: {
      bigR: { x: noncePoint.slice(1, 33).reverse(), y: noncePoint.slice(33) },
      s: getBytes(signature.s).reverse(),
      recoveryId: BigInt(signature.yParity),
    },
  };
};
const responseKey = {
  x: BigInt(`0x${signingKey.publicKey.slice(4, 68)}`),
  y: BigInt(`0x${signingKey.publicKey.slice(68)}`),
  identity: false,
};
const response = signedResponse(0, data);
assert.ok(pureCircuits.verify32(data, response, responseKey));
assert.equal(pureCircuits.verify32(data, { ...response, blockHeight: 43n }, responseKey), false);
assert.equal(
  pureCircuits.verify32(
    data,
    { ...response, requestId: new Uint8Array(32).fill(0x30) },
    responseKey,
  ),
  false,
);
for (const kind of [0, 1, 2] as const) {
  const empty = new Uint8Array();
  const response = signedResponse(kind, empty);
  assert.ok(pureCircuits.verify0(empty, response, responseKey));
  assert.equal(
    pureCircuits.verify0(empty, { ...response, outputKind: (kind + 1) % 3 }, responseKey),
    false,
  );
}

const singleton = new SingletonContract({});
const singletonInitial = await singleton.initialState(
  createConstructorContext({}, "44".repeat(32)),
);
const wireResponse = {
  ...response,
  signature: {
    ...response.signature,
    bigR: { ...response.signature.bigR, x: Uint8Array.from(response.signature.bigR.x).reverse() },
    s: Uint8Array.from(response.signature.s).reverse(),
  },
};
const emitted = await singleton.circuits.respondBidirectional(
  createCircuitContext(
    "respondBidirectional",
    "ab".repeat(32),
    "44".repeat(32),
    singletonInitial.currentContractState,
    {},
  ),
  wireResponse,
);
const [event] = decodeSignetLogEvents(emitted.context.events);
assert.ok(event);
assert.deepEqual(decodeRespondBidirectionalEventPayload(event.payload).event, wireResponse);
const responseEvent = {
  payload: hex(event.payload),
  requestId: hex(wireResponse.requestId),
  blockHeight: wireResponse.blockHeight.toString(),
  outputKind: wireResponse.outputKind,
  serializedOutputLength: wireResponse.serializedOutputLength.toString(),
  digest: hex(wireResponse.digest),
  signature: {
    bigR: { x: hex(wireResponse.signature.bigR.x), y: hex(wireResponse.signature.bigR.y) },
    s: hex(wireResponse.signature.s),
    recoveryId: Number(wireResponse.signature.recoveryId),
  },
};

const fixture = {
  responseEvent,
  compiler: "0.33.0-rc.2",
  runtime: "0.18.0-rc.1",
  reference: "@sig-net/midnight@0.24.0-rc.3/src/Signet.compact",
  referenceCommit: "5caf03623a1a5055b884f594e297076de689be2a",
  request: requestVectors[0],
  requestVectors,
  attestations: vectors.map((vector) => ({
    requestId: hex(rid),
    keyVersion: Number(vector.keyVersion),
    kind: Number(vector.kind),
    blockHeight: vector.blockHeight.toString(),
    data: hex(vector.data),
    digest: hex(vector.digest),
    cache: hex(vector.cache),
  })),
};
writeFileSync(
  new URL("../../../chain-midnight/fixtures/api-parity-vectors.json", import.meta.url),
  `${JSON.stringify(fixture, null, 2)}\n`,
);
console.log(
  `generated ${requestVectors.length} request and ${vectors.length} Compact attestation vectors`,
);
