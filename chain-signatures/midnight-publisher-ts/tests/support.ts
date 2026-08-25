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
import { deriveAccountKeys } from "@sig-net/midnight-contract-deploy";

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

export const testConfig = (overrides: Partial<Config> = {}): Config => ({
  networkId: "undeployed",
  endpoints: {
    nodeUrl: "http://127.0.0.1:9944/",
    proofServerUrl: "http://127.0.0.1:6300/",
    indexerUrl: "http://127.0.0.1:8088/api/v3/graphql",
    indexerWsUrl: "ws://127.0.0.1:8088/api/v3/graphql/ws",
  },
  accountKeys: deriveAccountKeys("ab".repeat(32), "undeployed"),
  ...overrides,
});

export const STUB_TX_ID = "ab".repeat(32);

export const SINGLETON = "d7b3c45da613be25050bbdf3fde4cef8f66154d3a52ca8c1edd878bd6391f169";
const REQUEST_ID = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";

export async function respondInput(
  overrides: Partial<BuildIntentInput> = {},
): Promise<BuildIntentInput> {
  return {
    circuit: "respond",
    contractAddress: SINGLETON,
    requestId: REQUEST_ID,
    signature: {
      bigR: { x: "11".repeat(32), y: "22".repeat(32) },
      s: "33".repeat(32),
      recoveryId: 0,
    },
    contractState: await initialSingletonStateHex(),
    ledgerParameters: toHex(LedgerParameters.initialParameters().serialize()),
    coinPublicKey: "44".repeat(32),
    ttlSeconds: 1_800_000_000,
    ...overrides,
  };
}

export interface StubEdges {
  readonly requireReady?: (timeoutMs: number) => Promise<void>;
  readonly proveTx?: (tx: unknown, proofBudgetMs: number) => Promise<unknown>;
  readonly balanceTx?: (tx: unknown) => Promise<unknown>;
  readonly finalizeTx?: (recipe: unknown) => Promise<unknown>;
  readonly submitTx?: (tx: unknown) => Promise<Landed>;
}

// Identity by default, so a sentinel passed in at one edge is observable at the next.
export function primeStub(edges: StubEdges = {}): void {
  primePublisher(
    Promise.resolve({
      proveTx: edges.proveTx ?? (async (tx: unknown, _proofBudgetMs: number) => tx),
      wallet: {
        requireReady: edges.requireReady ?? (async () => undefined),
        balanceTx: edges.balanceTx ?? (async (tx: unknown) => tx),
        finalizeTx: edges.finalizeTx ?? (async (recipe: unknown) => recipe),
        submitTx: edges.submitTx ?? (async () => ({ txId: STUB_TX_ID })),
        close: async () => undefined,
      } as unknown as FundingWallet,
    } as unknown as Publisher),
  );
}

export const decodeIntent = (bytes: Uint8Array) =>
  Intent.deserialize("signature", "pre-proof", "pre-binding", bytes);

// The entry point distinguishes the two response circuits without depending on
// compiler-generated transcript details.
export function calledEntryPoint(bytes: Uint8Array): string {
  const [action] = decodeIntent(bytes).actions;
  if (!(action instanceof ContractCall))
    throw new Error("expected the intent's one action to be a contract call");
  return String(action.entryPoint);
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
