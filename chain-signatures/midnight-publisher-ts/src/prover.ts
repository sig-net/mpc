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

import { PublisherError } from "./errors.js";

export type UnboundTransaction = Transaction<SignatureEnabled, Proof, PreBinding>;

const BUILTIN_PREFIX = "midnight/";

// The key location arrives inside caller-supplied bytes and becomes a path; refusing
// anything but a compactc artifact name stops the wire choosing which file is read.
const CIRCUIT_NAME = /^[A-Za-z][A-Za-z0-9_]*$/;

async function keyMaterial(managedDir: string, keyLocation: string): Promise<ProvingKeyMaterial> {
  if (!CIRCUIT_NAME.test(keyLocation)) {
    throw new PublisherError("bad_request", `the intent names an unusable key location \`${keyLocation}\``);
  }

  const artifact = async (directory: string, extension: string): Promise<Uint8Array> => {
    try {
      return Uint8Array.from(await readFile(join(managedDir, directory, `${keyLocation}.${extension}`)));
    } catch (cause) {
      throw new PublisherError(
        "contract_mismatch",
        `no ${extension} for circuit \`${keyLocation}\` in ${managedDir}; ` +
          `rebuild the contract assets or repoint MIDNIGHT_PUB_MANAGED_DIR`,
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

export function provingProvider(managedDir: string, proofServerUrl: string): ProvingProvider {
  // Read per call: a cache would outlive a redeployed managed dir.
  const material = async (keyLocation: string): Promise<ProvingKeyMaterial | undefined> =>
    keyLocation.startsWith(BUILTIN_PREFIX) ? undefined : keyMaterial(managedDir, keyLocation);

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
  managedDir: string,
  proofServerUrl: string,
  transaction: UnprovenTransaction,
): Promise<UnboundTransaction> {
  return transaction.prove(provingProvider(managedDir, proofServerUrl), CostModel.initialCostModel());
}
