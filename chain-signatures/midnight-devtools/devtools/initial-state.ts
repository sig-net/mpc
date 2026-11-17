import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { createConstructorContext } from "@midnight-ntwrk/compact-runtime";
import {
  Contract as SignetResponder,
  createSignetResponderPrivateState,
  witnesses,
  type SignetResponderPrivateState,
} from "@sig-net/midnight-responder";

// The installed package's compiled assets: `keys/` and `zkir/`.
export function managedDir(): string {
  const { resolve } = createRequire(import.meta.url);
  return join(dirname(resolve("@sig-net/midnight-responder")), "managed");
}

// The responder's initial state, synthesized from the installed contract package and
// populated with the verifier keys that deployment puts on chain.
export async function initialResponderState(): Promise<Uint8Array> {
  const contract = new SignetResponder<SignetResponderPrivateState>(witnesses);
  const { currentContractState } = await contract.initialState(
    createConstructorContext(createSignetResponderPrivateState(), "44".repeat(32)),
  );
  for (const circuit of ["respond", "respondBidirectional"]) {
    const operation = currentContractState.operation(circuit);
    if (operation === undefined) throw new Error(`initial state has no ${circuit} operation`);
    operation.verifierKey = readFileSync(`${managedDir()}/keys/${circuit}.verifier`);
    currentContractState.setOperation(circuit, operation);
  }
  return currentContractState.serialize();
}
