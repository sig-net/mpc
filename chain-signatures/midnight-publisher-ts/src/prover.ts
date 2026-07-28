// The proof server, plus the one thing it cannot resolve on its own.
//
// A proof preimage names its circuit by key location. The server holds the protocol's
// own keys, so everything under `midnight/` (zswap, dust) is left to it, and it answers
// `bad input` for anything else. A contract call is anything else: `respond`'s prover
// key, verifier key and IR live in the operator's managed dir, so they travel in the
// payload the wallet SDK's own HTTP prover client never sends.
//
// Proving happens HERE and not inside the wallet's `finalizeRecipe`, which uses that
// client: the call has to be proven before the wallet balances it, because balancing
// prices a transaction whose proof sizes are already known.

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

/** Proven and not yet bound: what the funding wallet balances. */
export type UnboundTransaction = Transaction<SignatureEnabled, Proof, PreBinding>;

// The protocol's own circuits. The server resolves these itself and rejects a payload
// that tries to supply them.
const BUILTIN_PREFIX = "midnight/";

// A key location is read out of caller-supplied intent bytes and is about to become a
// path. `compactc` names its artifacts after the circuit, so anything with a separator
// or a dot in it is not one, and refusing the shape is what stops the wire from
// choosing which file this process reads.
const CIRCUIT_NAME = /^[A-Za-z][A-Za-z0-9_]*$/;

async function keyMaterial(managedDir: string, keyLocation: string): Promise<ProvingKeyMaterial> {
  if (!CIRCUIT_NAME.test(keyLocation)) {
    throw new PublisherError("bad_request", `the intent names an unusable key location \`${keyLocation}\``);
  }

  // The layout `compactc` writes, and the same one the SDK's own key material provider
  // fetches the protocol circuits under.
  const artifact = async (directory: string, extension: string): Promise<Uint8Array> => {
    try {
      return Uint8Array.from(await readFile(join(managedDir, directory, `${keyLocation}.${extension}`)));
    } catch (cause) {
      // The managed dir was built for a different contract than the one the caller ran
      // the circuit against. Same remedy as an absent entry point, one step later.
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

/**
 * The provider the ledger drives while proving. Exported for the tests that pin what it
 * will and will not read off disk: every key location it is asked for arrives inside
 * caller-supplied bytes.
 */
export function provingProvider(managedDir: string, proofServerUrl: string): ProvingProvider {
  // Read per call rather than cached: the prover key is under a megabyte, the proof it
  // feeds takes seconds, and a cache would outlive a redeployed managed dir.
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

/**
 * Proves every call in `transaction` on the proof server.
 *
 * The initial cost model, which is what the SDK's own proving paths use: it prices the
 * proof, not the transaction, and the fee the wallet then pays is priced from the chain.
 */
export function proveTransaction(
  managedDir: string,
  proofServerUrl: string,
  transaction: UnprovenTransaction,
): Promise<UnboundTransaction> {
  return transaction.prove(provingProvider(managedDir, proofServerUrl), CostModel.initialCostModel());
}
