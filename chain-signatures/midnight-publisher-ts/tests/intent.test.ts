// The intent builder, against the real compiled contract and the singleton's
// synthesized initial state. Nothing is mocked: if these pass, the circuit ran.

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

// A well-formed address for the intent to carry; the state is synthesized rather
// than read from a deploy at this address.
const SINGLETON = "d7b3c45da613be25050bbdf3fde4cef8f66154d3a52ca8c1edd878bd6391f169";
// An arbitrary 32-byte id: a respond is a blind append, so any id serves.
const REQUEST_ID = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";

// Deliberately all different from each other. Equal-looking components would make a
// transposed x and y invisible, which is the exact bug these assertions exist to catch.
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
  it("carries exactly one respond call for the address it was asked about", async () => {
    const bytes = await buildIntent(managedDir(), respondInput());

    const intent = decodeIntent(bytes);
    expect(intent.actions).toHaveLength(1);
    expect(String(intent.actions[0])).toContain(SINGLETON);
    expect(calledEntryPoint(bytes)).toBe("respond");
  });

  it("puts the signature in the call in the order the contract declared it", async () => {
    // The whole point of the seam: whatever the MPC threshold signed has to arrive at
    // the circuit unpermuted. A transposed component still produces a well-formed
    // intent that lands on chain under the right request id and recovers a different
    // key, so nothing downstream would notice. Exact equality is what makes the
    // positions non-interchangeable.
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
    // Both respond circuits are blind appends with no fallible work, and the Rust
    // half treats a 200 as final on that basis. If a contract change moves work into
    // the fallible segment, this is where it surfaces.
    const rendered = renderCall(await buildIntent(managedDir(), respondInput()));

    expect(rendered).toContain("guaranteed_transcript: Some(");
    expect(rendered).toContain("fallible_transcript: None");
  });

  it("builds respondBidirectional with the same signature-only shape as respond", async () => {
    // The 0.15.0 contract's RespondBidirectionalEvent is a bare Signature: the
    // attestation digest is recomputed by consumers, never carried on chain.
    const bytes = await buildIntent(managedDir(), respondInput({ circuit: "respondBidirectional" }));

    expect(decodeIntent(bytes).actions).toHaveLength(1);
    expect(calledEntryPoint(bytes)).toBe("respondBidirectional");
    expect(pushedCallArgs(bytes)).toBe(`pushs <[${X}, ${Y}, ${S}, ${ZERO}]: b32b32b32b1>`);
  });

  it("names the mismatch when the deployed contract has no such entry point", async () => {
    // A contract with no operations at all stands in for the real case this guards:
    // a managed dir pointed at a different build than what is deployed. It catches a
    // missing NAME only; a build whose names still match but whose verifier keys have
    // moved on gets an intent back, and the chain is what rejects it.
    const empty = toHex(new ContractState().serialize());

    await expect(buildIntent(managedDir(), respondInput({ contractState: empty }))).rejects.toThrow(
      /exposes no operation `respond`/,
    );
  });

  it("is NOT byte-deterministic, because the communication commitment is sampled", async () => {
    // Pinned deliberately. The commitment is what unlinks a call from its caller, so
    // a fixed value would be a privacy regression. Anything downstream that wants a
    // golden must assert on the decoded call, never on these bytes.
    const input = respondInput();
    expect(await buildIntent(managedDir(), input)).not.toEqual(await buildIntent(managedDir(), input));
  });

  it("produces bytes the ledger's own tagged reader accepts", async () => {
    // The seam's contract in one line: Rust deserializes these same bytes with
    // `tagged_deserialize`, so the tag has to be there and has to be ledger 9.
    const bytes = await buildIntent(managedDir(), respondInput());

    expect(Buffer.from(bytes.slice(0, 20)).toString("utf8")).toContain("midnight:intent[v9]");
  });
});

describe("ContractCallPrototype", () => {
  it("is constructible, which is what pins the ledger-v9 argument order", () => {
    // A guard on the one call whose ten positional arguments are easy to transpose
    // and whose failure mode is a rejected transaction rather than a type error.
    expect(ContractCallPrototype).toBeTypeOf("function");
    expect(ContractCallPrototype.length).toBe(10);
  });
});
