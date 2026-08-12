import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { ContractCall, Intent, LedgerParameters } from "@midnightntwrk/ledger-v9";
import { createConstructorContext } from "@midnight-ntwrk/compact-runtime";
import {
  Contract as SignetContract,
  createSignetContractPrivateState,
  witnesses,
  type SignetContractPrivateState,
} from "@sig-net/midnight-contract";

import type { Config } from "../src/config.js";
import type { BuildIntentInput } from "../src/intent.js";
import { primePublisher, type Publisher } from "../src/submit.js";
import type { FundingWallet, Landed } from "../src/wallet.js";

export const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

// The real compiled assets, not the fixtures directory: a circuit run reads `keys/` and `zkir/`.
export function managedDir(): string {
  const { resolve } = createRequire(import.meta.url);
  return join(dirname(resolve("@sig-net/midnight-contract")), "managed");
}

// No endpoints: the submit path can only reach a wallet a test primed by hand.
export const testConfig = (overrides: Partial<Config> = {}): Config => ({
  networkId: "undeployed",
  endpoints: undefined,
  ...overrides,
});

export const STUB_TX_ID = "ab".repeat(32);

export const SINGLETON = "d7b3c45da613be25050bbdf3fde4cef8f66154d3a52ca8c1edd878bd6391f169";
export const REQUEST_ID = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";

export async function respondInput(overrides: Partial<BuildIntentInput> = {}): Promise<BuildIntentInput> {
  return {
    circuit: "respond",
    contractAddress: SINGLETON,
    requestId: REQUEST_ID,
    signature: { bigR: { x: "11".repeat(32), y: "22".repeat(32) }, s: "33".repeat(32), recoveryId: 0 },
    contractState: await initialSingletonStateHex(),
    ledgerParameters: toHex(LedgerParameters.initialParameters().serialize()),
    coinPublicKey: "44".repeat(32),
    ttlSeconds: 1_800_000_000,
    ...overrides,
  };
}

export interface StubEdges {
  readonly proveTx?: (tx: unknown) => Promise<unknown>;
  readonly balanceTx?: (tx: unknown) => Promise<unknown>;
  readonly finalizeTx?: (recipe: unknown) => Promise<unknown>;
  readonly submitTx?: (tx: unknown) => Promise<Landed>;
}

// Identity by default, so a sentinel passed in at one edge is observable at the next.
export function primeStub(edges: StubEdges = {}): void {
  primePublisher(
    Promise.resolve({
      proveTx: edges.proveTx ?? (async (tx: unknown) => tx),
      wallet: {
        balanceTx: edges.balanceTx ?? (async (tx: unknown) => tx),
        finalizeTx: edges.finalizeTx ?? (async (recipe: unknown) => recipe),
        submitTx: edges.submitTx ?? (async () => ({ txId: STUB_TX_ID })),
        close: async () => undefined,
      } as unknown as FundingWallet,
    } as unknown as Publisher),
  );
}

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

// The singleton's initial state, synthesized from the installed contract package and
// populated with the verifier keys that deployment puts on chain.
export function initialSingletonStateHex(): Promise<string> {
  singletonStateHex ??= (async () => {
    const contract = new SignetContract<SignetContractPrivateState>(witnesses);
    const { currentContractState } = await contract.initialState(
      createConstructorContext(createSignetContractPrivateState(), "44".repeat(32)),
    );
    for (const circuit of ["respond", "respondBidirectional", "signBidirectional"]) {
      const operation = currentContractState.operation(circuit);
      if (operation === undefined) throw new Error(`initial state has no ${circuit} operation`);
      operation.verifierKey = readFileSync(`${managedDir()}/keys/${circuit}.verifier`);
      currentContractState.setOperation(circuit, operation);
    }
    return toHex(currentContractState.serialize());
  })();
  return singletonStateHex;
}
