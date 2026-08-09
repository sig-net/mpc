// The intent builder against the real compiled contract: nothing is mocked, so if
// these pass, the circuit ran.

import { describe, expect, it } from "vitest";

import { ContractCallPrototype, LedgerParameters } from "@midnightntwrk/ledger-v9";
import { ContractState } from "@midnight-ntwrk/compact-runtime";

import { buildIntent, type BuildIntentInput } from "../src/intent.js";
import {
  calledEntryPoint,
  decodeIntent,
  initialSingletonStateHex,
  managedDir,
  pushedCallArgs,
  renderCall,
  toHex,
} from "./support.js";

const CONTRACT_STATE = await initialSingletonStateHex();

const SINGLETON = "d7b3c45da613be25050bbdf3fde4cef8f66154d3a52ca8c1edd878bd6391f169";
const REQUEST_ID = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";

// All different, so a transposed component cannot look correct.
const X = "11".repeat(32);
const Y = "22".repeat(32);
const S = "33".repeat(32);

const SIGNATURE = {
  bigR: { x: X, y: Y },
  s: S,
  recoveryId: 0 as const,
};

// The transcript renders a trailing-zero-trimmed value, so a zero byte is `-`.
const ZERO = "-";

const respondInput = (overrides: Partial<BuildIntentInput> = {}): BuildIntentInput => ({
  circuit: "respond",
  contractAddress: SINGLETON,
  requestId: REQUEST_ID,
  signature: SIGNATURE,
  contractState: CONTRACT_STATE,
  ledgerParameters: toHex(LedgerParameters.initialParameters().serialize()),
  coinPublicKey: "44".repeat(32),
  ttlSeconds: 1_800_000_000,
  ...overrides,
});

describe("buildIntent", () => {
  it("carries exactly one tagged respond call for the address it was asked about", async () => {
    const bytes = await buildIntent(managedDir(), respondInput());

    const intent = decodeIntent(bytes);
    expect(intent.actions).toHaveLength(1);
    expect(String(intent.actions[0])).toContain(SINGLETON);
    expect(calledEntryPoint(bytes)).toBe("respond");
    expect(Buffer.from(bytes.slice(0, 20)).toString("utf8")).toContain("midnight:intent[v9]");
  });

  it("puts the signature in the call in the order the contract declared it", async () => {
    // A transposed component still lands on chain under the right request id and
    // recovers a different key; only exact positional equality catches it.
    const args = pushedCallArgs(await buildIntent(managedDir(), respondInput()));

    expect(args).toBe(`pushs <[${X}, ${Y}, ${S}, ${ZERO}]: b32b32b32b1>`);
  });

  it("carries the recovery id, which selects which key the signature recovers to", async () => {
    const args = await buildIntent(managedDir(), respondInput({ signature: { ...SIGNATURE, recoveryId: 1 } }));

    expect(pushedCallArgs(args)).toBe(`pushs <[${X}, ${Y}, ${S}, 01]: b32b32b32b1>`);
  });

  it("answers about the request id it was given, not some other one", async () => {
    const rendered = renderCall(await buildIntent(managedDir(), respondInput()));

    expect(rendered).toContain(`push <[${REQUEST_ID}]: b32>`);
  });

  it("puts the whole call in the guaranteed segment", async () => {
    // The Rust half treats a 200 as final on this basis.
    const rendered = renderCall(await buildIntent(managedDir(), respondInput()));

    expect(rendered).toContain("guaranteed_transcript: Some(");
    expect(rendered).toContain("fallible_transcript: None");
  });

  it("builds respondBidirectional with the same signature-only shape as respond", async () => {
    const bytes = await buildIntent(managedDir(), respondInput({ circuit: "respondBidirectional" }));

    expect(decodeIntent(bytes).actions).toHaveLength(1);
    expect(calledEntryPoint(bytes)).toBe("respondBidirectional");
    expect(pushedCallArgs(bytes)).toBe(`pushs <[${X}, ${Y}, ${S}, ${ZERO}]: b32b32b32b1>`);
  });

  it("names the mismatch when the deployed contract has no such entry point", async () => {
    const empty = toHex(new ContractState().serialize());

    await expect(buildIntent(managedDir(), respondInput({ contractState: empty }))).rejects.toThrow(
      /exposes no operation `respond`/,
    );
  });

  it("is NOT byte-deterministic, because the communication commitment is sampled", async () => {
    const input = respondInput();
    expect(await buildIntent(managedDir(), input)).not.toEqual(await buildIntent(managedDir(), input));
  });
});

describe("ContractCallPrototype", () => {
  it("is constructible, which is what pins the ledger-v9 argument order", () => {
    // Ten positional arguments whose failure mode is a rejected transaction, not a type error.
    expect(ContractCallPrototype).toBeTypeOf("function");
    expect(ContractCallPrototype.length).toBe(10);
  });
});
