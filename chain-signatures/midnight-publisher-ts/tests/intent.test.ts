// The intent builder against the real compiled contract: nothing is mocked, so if
// these pass, the circuit ran.

import { readFileSync } from "node:fs";

import { afterEach, describe, expect, it, vi } from "vitest";

import { ContractOperation, ContractState } from "@midnight-ntwrk/compact-runtime";
import { ContractCall, type Proofish } from "@midnightntwrk/ledger-v9";

import { decodeRespondBidirectionalEventPayload } from "@sig-net/midnight";

import { buildIntent } from "../src/intent.js";
import {
  calledEntryPoint,
  decodeIntent,
  initialSingletonStateHex,
  managedDir,
  respondInput,
  toHex,
} from "./support.js";

const CONTRACT_STATE = await initialSingletonStateHex();

function onlyCall(bytes: Uint8Array): ContractCall<Proofish> {
  const intent = decodeIntent(bytes);
  expect(intent.actions).toHaveLength(1);
  const [call] = intent.actions;
  expect(call).toBeInstanceOf(ContractCall);
  if (!(call instanceof ContractCall)) throw new Error("expected a contract call");
  return call;
}

function storageWrites(call: ContractCall<Proofish>): unknown[] {
  const program = call.guaranteedTranscript?.program;
  expect(program).toBeDefined();
  if (program === undefined) throw new Error("expected a guaranteed transcript");
  return program.filter((op) => typeof op !== "string" && "push" in op && op.push.storage);
}

afterEach(() => vi.unstubAllEnvs());

describe("buildIntent", () => {
  it("takes its configuration from the caller, never from the process environment", async () => {
    // These are the names platform-js's own provider would read ahead of the caller's values.
    vi.stubEnv("NETWORK", "base_sepolia");
    vi.stubEnv("KEYS_COIN_PUBLIC", "not-a-key");
    vi.stubEnv("KEYS_SIGNING", "not-a-key");
    vi.stubEnv("KEYS_SIGNING_KIND", "not-a-kind");

    const bytes = await buildIntent(await respondInput());

    expect(calledEntryPoint(bytes)).toBe("respond");
    const call = onlyCall(bytes);
    expect(call.guaranteedTranscript).toBeDefined();
    expect(call.fallibleTranscript).toBeUndefined();
    expect(storageWrites(call)).toHaveLength(0);
  });

  it("builds one guaranteed respond call without storage writes", async () => {
    const input = await respondInput();
    const bytes = await buildIntent({ ...input, signature: { ...input.signature, recoveryId: 1 } });

    const call = onlyCall(bytes);
    expect(call.address).toBe(input.contractAddress);
    expect(calledEntryPoint(bytes)).toBe("respond");
    expect(call.guaranteedTranscript).toBeDefined();
    expect(call.fallibleTranscript).toBeUndefined();
    expect(storageWrites(call)).toHaveLength(0);
    const intent = decodeIntent(bytes);
    expect(intent.ttl.getTime()).toBe(input.ttlSeconds * 1_000);
    expect(Buffer.from(bytes.slice(0, 20)).toString("utf8")).toContain("midnight:intent[v9]");
  });

  it("builds respondBidirectional without storage writes", async () => {
    const input = await respondInput({
      circuit: "respondBidirectional",
      attestation: {
        blockHeight: "18364758544493064720",
        outputKind: 2,
        serializedOutputLength: "0",
        digest: "55".repeat(32),
      },
    });
    const bytes = await buildIntent(input);

    expect(calledEntryPoint(bytes)).toBe("respondBidirectional");
    const call = onlyCall(bytes);
    const push = call.guaranteedTranscript?.program.find(
      (op) => typeof op !== "string" && "push" in op,
    );
    if (
      push === undefined ||
      typeof push === "string" ||
      !("push" in push) ||
      push.push.value.tag !== "array"
    )
      throw new Error("missing event push");
    const event = push.push.value.content[2];
    if (event?.tag !== "cell") throw new Error("missing misc event cell");
    const bytes288 = new Uint8Array(288);
    bytes288.set(event.content.value[0]!);
    const decoded = decodeRespondBidirectionalEventPayload(bytes288.slice(32)).event;
    expect(decoded).toEqual({
      requestId: Uint8Array.from(Buffer.from(input.requestId, "hex")),
      blockHeight: BigInt(input.attestation!.blockHeight),
      outputKind: 2,
      serializedOutputLength: 0n,
      digest: Uint8Array.from(Buffer.from(input.attestation!.digest, "hex")),
      signature: {
        bigR: {
          x: Uint8Array.from(Buffer.from(input.signature.bigR.x, "hex")),
          y: Uint8Array.from(Buffer.from(input.signature.bigR.y, "hex")),
        },
        s: Uint8Array.from(Buffer.from(input.signature.s, "hex")),
        recoveryId: BigInt(input.signature.recoveryId),
      },
    });
    expect(call.guaranteedTranscript).toBeDefined();
    expect(call.fallibleTranscript).toBeUndefined();
    expect(storageWrites(call)).toHaveLength(0);
  });

  it("names the mismatch when the deployed respond is absent, proofless, or differently keyed", async () => {
    const differing = ContractState.deserialize(Buffer.from(CONTRACT_STATE, "hex"));
    const operation = differing.operation("respond")!;
    operation.verifierKey = readFileSync(`${managedDir()}/keys/respondBidirectional.verifier`);
    differing.setOperation("respond", operation);
    const proofless = ContractState.deserialize(Buffer.from(CONTRACT_STATE, "hex"));
    proofless.setOperation("respond", new ContractOperation());
    const cases: readonly [ContractState, RegExp][] = [
      [new ContractState(), /exposes no operation `respond`/],
      [proofless, /no verifier key/],
      [differing, /different verifier key/],
    ];

    for (const [state, detail] of cases) {
      await expect(
        buildIntent(await respondInput({ contractState: toHex(state.serialize()) })),
      ).rejects.toMatchObject({
        code: "contract_mismatch",
        message: expect.stringMatching(detail),
      });
    }
  });
});
