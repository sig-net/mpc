// The proof server holds only the protocol's own keys (`midnight/...`); a contract
// call's prover key, verifier key and IR live in the managed dir and travel in the
// payload. Proving happens before the wallet balances: balancing prices the proof sizes.

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import {
  CostModel,
  createCheckPayload,
  createProvingPayload,
  parseCheckResult,
  type PreBinding,
  type Proof,
  type ProvingKeyMaterial,
  type ProvingProvider,
  type SignatureEnabled,
  type Transaction,
  type UnprovenTransaction,
} from "@midnightntwrk/ledger-v9";
import { signetContractManagedPath } from "@sig-net/midnight-contract-deploy";

import { PublisherError } from "./errors.js";
import { RESPOND_CIRCUITS, type RespondCircuit } from "./intent.js";

export type UnboundTransaction = Transaction<SignatureEnabled, Proof, PreBinding>;

const BUILTIN_PREFIX = "midnight/";

function isRespondCircuit(keyLocation: string): keyLocation is RespondCircuit {
  return RESPOND_CIRCUITS.some((circuit) => circuit === keyLocation);
}

async function keyMaterial(keyLocation: RespondCircuit): Promise<ProvingKeyMaterial> {
  const artifact = async (directory: string, extension: string): Promise<Uint8Array> => {
    try {
      return Uint8Array.from(
        await readFile(join(signetContractManagedPath, directory, `${keyLocation}.${extension}`)),
      );
    } catch (cause) {
      throw new PublisherError(
        "contract_mismatch",
        `the packaged contract has no ${extension} for circuit \`${keyLocation}\``,
        { cause },
      );
    }
  };

  const [proverKey, verifierKey, ir] = await Promise.all([
    artifact("keys", "prover"),
    artifact("keys", "verifier"),
    artifact("zkir", "bzkir"),
  ]);
  return { proverKey, verifierKey, ir };
}

async function post(proofServerUrl: string, path: string, body: Uint8Array): Promise<Uint8Array> {
  const response = await fetch(new URL(path, proofServerUrl), {
    method: "POST",
    headers: { "content-type": "application/octet-stream" },
    body,
  });
  if (response.status !== 200) {
    throw new Error(`proof server answered ${response.status} to ${path}: ${await response.text()}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

export function provingProvider(proofServerUrl: string): ProvingProvider {
  const material = async (keyLocation: string): Promise<ProvingKeyMaterial | undefined> => {
    if (keyLocation.startsWith(BUILTIN_PREFIX)) return undefined;
    if (!isRespondCircuit(keyLocation)) {
      throw new PublisherError("bad_request", `the intent names an unsupported key location \`${keyLocation}\``);
    }
    return keyMaterial(keyLocation);
  };

  return {
    check: async (preimage, keyLocation) =>
      parseCheckResult(
        await post(proofServerUrl, "/check", createCheckPayload(preimage, (await material(keyLocation))?.ir)),
      ),
    prove: async (preimage, keyLocation, overwriteBindingInput) =>
      post(
        proofServerUrl,
        "/prove",
        createProvingPayload(preimage, overwriteBindingInput, await material(keyLocation)),
      ),
    lookupKey: (keyLocation) => material(keyLocation),
  };
}

export function proveTransaction(
  proofServerUrl: string,
  transaction: UnprovenTransaction,
): Promise<UnboundTransaction> {
  return transaction.prove(provingProvider(proofServerUrl), CostModel.initialCostModel());
}
