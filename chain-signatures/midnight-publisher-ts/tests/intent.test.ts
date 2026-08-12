// The intent builder against the real compiled contract: nothing is mocked, so if
// these pass, the circuit ran.

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { ContractOperation, ContractState } from "@midnight-ntwrk/compact-runtime";

import { buildIntent } from "../src/intent.js";
import {
  calledEntryPoint,
  decodeIntent,
  initialSingletonStateHex,
  managedDir,
  pushedCallArgs,
  respondInput,
  renderCall,
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
    const rendered = renderCall(bytes);
    expect(intent.actions).toHaveLength(1);
    expect(String(intent.actions[0])).toContain(input.contractAddress);
    expect(calledEntryPoint(bytes)).toBe("respond");
    expect(pushedCallArgs(bytes)).toBe(`pushs <[${X}, ${Y}, ${S}, 01]: b32b32b32b1>`);
    expect(rendered).toContain(`push <[${input.requestId}]: b32>`);
    expect(rendered).toContain("guaranteed_transcript: Some(");
    expect(rendered).toContain("fallible_transcript: None");
    expect(Buffer.from(bytes.slice(0, 20)).toString("utf8")).toContain("midnight:intent[v9]");
  });

  it("builds respondBidirectional with the same signature-only shape as respond", async () => {
    const bytes = await buildIntent(await respondInput({ circuit: "respondBidirectional" }));

    expect(decodeIntent(bytes).actions).toHaveLength(1);
    expect(calledEntryPoint(bytes)).toBe("respondBidirectional");
    expect(pushedCallArgs(bytes)).toBe(`pushs <[${X}, ${Y}, ${S}, -]: b32b32b32b1>`);
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
