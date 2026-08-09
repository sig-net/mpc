// Shared test scaffolding: the arrange step only.

import { createRequire } from "node:module";
import { dirname, join } from "node:path";

import { ContractCall, Intent } from "@midnightntwrk/ledger-v9";
import { createConstructorContext } from "@midnight-ntwrk/compact-runtime";
import {
  Contract as SignetContract,
  createSignetContractPrivateState,
  witnesses,
  type SignetContractPrivateState,
} from "@sig-net/midnight-contract";

import type { Config } from "../src/config.js";

export const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

// The REAL compiled assets, not the fixtures directory: a circuit run reads `keys/`
// and `zkir/`, so pointing this at the fixture folder fails with a missing-asset error
// that reads like a bug in the builder rather than like a misconfigured test.
export function managedDir(): string {
  const { resolve } = createRequire(import.meta.url);
  return join(dirname(resolve("@sig-net/midnight-contract")), "managed");
}

// No endpoints, which is what makes it safe to run: the submit path can only reach a
// wallet a test primed by hand. Anything that forgets to prime one answers rather than
// dialling an address.
export const testConfig = (overrides: Partial<Config> = {}): Config => ({
  managedDir: managedDir(),
  networkId: "undeployed",
  endpoints: undefined,
  ...overrides,
});

// The markers are the literal instance tags, not classes.
export const decodeIntent = (bytes: Uint8Array) => Intent.deserialize("signature", "pre-proof", "pre-binding", bytes);

export const renderCall = (bytes: Uint8Array): string => String(decodeIntent(bytes).actions[0]);

// Both respond circuits push byte-identical signature-only args; the entry point is
// the stable route discriminator (their transcripts also differ in which ledger cells
// they write, but those indices are compiler-assigned and contract-version-coupled).
export function calledEntryPoint(bytes: Uint8Array): string {
  const [action] = decodeIntent(bytes).actions;
  if (!(action instanceof ContractCall)) throw new Error("expected the intent's one action to be a contract call");
  return String(action.entryPoint);
}

/**
 * The circuit's arguments as the transcript pushed them: one `pushs` op whose tuple IS
 * the event struct, in the order the contract declared it, tagged with each field's
 * width. It is the only place the argument VALUES survive into the intent, so it is the
 * only thing that can tell a correct call from one whose fields were transposed,
 * dropped or zeroed. Both circuits end in the signature's `b32b32b32b1`, which is what
 * distinguishes this op from the transcript's other pushes.
 *
 * Byte goldens cannot do this job: `buildIntent` samples a fresh communication
 * commitment per call, so the bytes differ every time and only the decode is stable.
 */
export function pushedCallArgs(bytes: Uint8Array): string {
  const ops = renderCall(bytes)
    .split("\n")
    .map((line) => line.trim().replace(/,$/, ""))
    .filter((op) => op.startsWith("pushs <[") && op.endsWith("b32b32b32b1>"));

  if (ops.length !== 1) throw new Error(`expected one argument push in the transcript, found ${ops.length}`);
  return ops[0]!;
}

let singletonStateHex: Promise<string> | undefined;

// The singleton's INITIAL state, synthesized from the installed contract package.
// It registers its operations as defaults with no embedded verifier keys; the
// entry-point lookup in `buildIntent` matches by name, so it works at any contract
// version and needs no chain capture. The absence of embedded keys is also what
// keeps the committed fixture byte-stable across contract bumps.
export function initialSingletonStateHex(): Promise<string> {
  singletonStateHex ??= (async () => {
    const contract = new SignetContract<SignetContractPrivateState>(witnesses);
    const { currentContractState } = await contract.initialState(
      createConstructorContext(createSignetContractPrivateState(), "44".repeat(32)),
    );
    return toHex(currentContractState.serialize());
  })();
  return singletonStateHex;
}
