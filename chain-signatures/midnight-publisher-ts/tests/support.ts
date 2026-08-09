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

// The real compiled assets, not the fixtures directory: a circuit run reads `keys/` and `zkir/`.
export function managedDir(): string {
  const { resolve } = createRequire(import.meta.url);
  return join(dirname(resolve("@sig-net/midnight-contract")), "managed");
}

// No endpoints: the submit path can only reach a wallet a test primed by hand.
export const testConfig = (overrides: Partial<Config> = {}): Config => ({
  managedDir: managedDir(),
  networkId: "undeployed",
  endpoints: undefined,
  ...overrides,
});

export const decodeIntent = (bytes: Uint8Array) => Intent.deserialize("signature", "pre-proof", "pre-binding", bytes);

export const renderCall = (bytes: Uint8Array): string => String(decodeIntent(bytes).actions[0]);

// Both respond circuits push byte-identical signature-only args; the entry point is the
// stable route discriminator (their ledger-cell writes also differ, but those indices
// are compiler-assigned and contract-version-coupled).
export function calledEntryPoint(bytes: Uint8Array): string {
  const [action] = decodeIntent(bytes).actions;
  if (!(action instanceof ContractCall)) throw new Error("expected the intent's one action to be a contract call");
  return String(action.entryPoint);
}

// The circuit's arguments as the transcript pushed them: the one `pushs` op ending in
// the signature's `b32b32b32b1` is the only place the argument VALUES survive into the
// intent, so it is the only thing that can catch transposed, dropped or zeroed fields.
// Byte goldens cannot: the communication commitment makes every build unique.
export function pushedCallArgs(bytes: Uint8Array): string {
  const ops = renderCall(bytes)
    .split("\n")
    .map((line) => line.trim().replace(/,$/, ""))
    .filter((op) => op.startsWith("pushs <[") && op.endsWith("b32b32b32b1>"));

  if (ops.length !== 1) throw new Error(`expected one argument push in the transcript, found ${ops.length}`);
  return ops[0]!;
}

let singletonStateHex: Promise<string> | undefined;

// The singleton's initial state, synthesized from the installed contract package. Its
// operations are registered as defaults with no embedded verifier keys, which is what
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
