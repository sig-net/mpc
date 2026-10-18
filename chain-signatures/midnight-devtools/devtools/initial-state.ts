import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { createConstructorContext } from "@midnight-ntwrk/compact-runtime";
import {
  Contract as SignetContract,
  createSignetContractPrivateState,
  witnesses,
  type SignetContractPrivateState,
} from "@sig-net/midnight-contract";

// The installed package's compiled assets: `keys/` and `zkir/`.
export function managedDir(): string {
  const { resolve } = createRequire(import.meta.url);
  return join(dirname(resolve("@sig-net/midnight-contract")), "managed");
}

// The singleton's initial state, synthesized from the installed contract package and
// populated with the verifier keys that deployment puts on chain.
export async function initialSingletonState(): Promise<Uint8Array> {
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
  return currentContractState.serialize();
}
