// The intent builder against the real compiled contract: nothing is mocked, so if
// these pass, the circuit ran.

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { ContractOperation, ContractState } from "@midnight-ntwrk/compact-runtime";
import { ContractCall } from "@midnightntwrk/ledger-v9";

import { buildIntent } from "../src/intent.js";
import {
  calledEntryPoint,
  decodeIntent,
  initialSingletonStateHex,
  managedDir,
  pushedCells,
  respondInput,
  toHex,
} from "./support.js";

const CONTRACT_STATE = await initialSingletonStateHex();

// All different, so a transposed component cannot look correct.
const X = "11".repeat(32);
const Y = "22".repeat(32);
const S = "33".repeat(32);

describe("buildIntent", () => {
  it("builds one guaranteed respond call with the exact wire arguments", async () => {
    const input = await respondInput();
    const bytes = await buildIntent({ ...input, signature: { ...input.signature, recoveryId: 1 } });

    const intent = decodeIntent(bytes);
    expect(intent.actions).toHaveLength(1);
    const [call] = intent.actions;
    expect(call).toBeInstanceOf(ContractCall);
    if (!(call instanceof ContractCall)) throw new Error("expected a contract call");
    expect(call.address).toBe(input.contractAddress);
    expect(calledEntryPoint(bytes)).toBe("respond");
    expect(pushedCells(bytes, true, [32, 32, 32, 1])).toEqual([[X, Y, S, "01"]]);
    expect(pushedCells(bytes, false, [32])).toContainEqual([input.requestId]);
    expect(call.guaranteedTranscript).toBeDefined();
    expect(call.fallibleTranscript).toBeUndefined();
    expect(intent.ttl.getTime()).toBe(input.ttlSeconds * 1_000);
    expect(Buffer.from(bytes.slice(0, 20)).toString("utf8")).toContain("midnight:intent[v9]");
  });

  it("builds respondBidirectional with the same signature-only shape as respond", async () => {
    const bytes = await buildIntent(await respondInput({ circuit: "respondBidirectional" }));

    expect(decodeIntent(bytes).actions).toHaveLength(1);
    expect(calledEntryPoint(bytes)).toBe("respondBidirectional");
    expect(pushedCells(bytes, true, [32, 32, 32, 1])).toEqual([[X, Y, S, ""]]);
  });

  it("names the mismatch when the deployed contract has no such entry point", async () => {
    const empty = toHex(new ContractState().serialize());

    await expect(buildIntent(await respondInput({ contractState: empty }))).rejects.toThrow(
      /exposes no operation `respond`/,
    );
  });

  it("rejects a deployed circuit with a different verifier key", async () => {
    const state = ContractState.deserialize(Buffer.from(CONTRACT_STATE, "hex"));
    const operation = state.operation("respond")!;
    operation.verifierKey = readFileSync(`${managedDir()}/keys/respondBidirectional.verifier`);
    state.setOperation("respond", operation);

    await expect(
      buildIntent(await respondInput({ contractState: toHex(state.serialize()) })),
    ).rejects.toMatchObject({ code: "contract_mismatch" });
  });

  it("rejects a deployed response circuit with no verifier key", async () => {
    const state = ContractState.deserialize(Buffer.from(CONTRACT_STATE, "hex"));
    state.setOperation("respond", new ContractOperation());

    await expect(
      buildIntent(await respondInput({ contractState: toHex(state.serialize()) })),
    ).rejects.toMatchObject({ code: "contract_mismatch" });
  });
});
