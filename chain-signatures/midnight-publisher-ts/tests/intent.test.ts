// The intent builder against the real compiled contract: nothing is mocked, so if
// these pass, the circuit ran.

import { readFileSync } from "node:fs";

import { afterEach, describe, expect, it, vi } from "vitest";

import { ContractOperation, ContractState } from "@midnight-ntwrk/compact-runtime";
import { ContractCall, type Proofish } from "@midnightntwrk/ledger-v9";

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
    const bytes = await buildIntent(await respondInput({ circuit: "respondBidirectional" }));

    expect(calledEntryPoint(bytes)).toBe("respondBidirectional");
    const call = onlyCall(bytes);
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
