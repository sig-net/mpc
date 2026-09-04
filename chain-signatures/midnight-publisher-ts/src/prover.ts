// The proof server holds only the protocol's own keys (`midnight/...`); a contract
// call's prover key, verifier key and IR live in the managed dir and travel in the
// payload. Proving happens before the wallet balances: balancing prices the proof sizes.

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { hashVerifierKey, parseContractKeyLocation } from "@midnight-ntwrk/compact-js";
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
import { expectedVk } from "@sig-net/midnight-contract";
import { signetContractManagedPath } from "@sig-net/midnight-contract-deploy";

import { PublisherError } from "./errors.js";
import { RESPOND_CIRCUITS, type RespondCircuit } from "./intent.js";

export type UnboundTransaction = Transaction<SignatureEnabled, Proof, PreBinding>;

const BUILTIN_PREFIX = "midnight/";

function isRespondCircuit(circuitId: string): circuitId is RespondCircuit {
  return RESPOND_CIRCUITS.some((circuit) => circuit === circuitId);
}

async function keyMaterial(
  circuit: RespondCircuit,
  verifierKeyHash: string,
): Promise<ProvingKeyMaterial> {
  const artifact = async (directory: string, extension: string): Promise<Uint8Array> => {
    try {
      return Uint8Array.from(
        await readFile(join(signetContractManagedPath, directory, `${circuit}.${extension}`)),
      );
    } catch (cause) {
      throw new PublisherError(
        "contract_mismatch",
        `the packaged contract has no ${extension} for circuit \`${circuit}\``,
        { cause },
      );
    }
  };

  const [proverKey, verifierKey, ir] = await Promise.all([
    artifact("keys", "prover"),
    artifact("keys", "verifier"),
    artifact("zkir", "bzkir"),
  ]);
  if (hashVerifierKey(verifierKey) !== verifierKeyHash) {
    throw new PublisherError(
      "contract_mismatch",
      `the packaged verifier key for circuit \`${circuit}\` does not match the intent`,
    );
  }
  return { proverKey, verifierKey, ir };
}

async function post(
  proofServerUrl: string,
  path: string,
  body: Uint8Array,
  signal: AbortSignal,
): Promise<Uint8Array> {
  const response = await fetch(new URL(path, proofServerUrl), {
    method: "POST",
    headers: { "content-type": "application/octet-stream" },
    body,
    signal,
  });
  if (response.status !== 200) {
    throw new Error(
      `proof server answered ${response.status} to ${path}: ${await response.text()}`,
    );
  }
  return new Uint8Array(await response.arrayBuffer());
}

export function provingProvider(proofServerUrl: string, signal: AbortSignal): ProvingProvider {
  const material = async (keyLocation: string): Promise<ProvingKeyMaterial | undefined> => {
    if (keyLocation.startsWith(BUILTIN_PREFIX)) return undefined;
    const location = parseContractKeyLocation(keyLocation);
    if (
      location === undefined ||
      !isRespondCircuit(location.circuitId) ||
      location.verifierKeyHash !== expectedVk[location.circuitId]
    ) {
      throw new PublisherError(
        "bad_request",
        `the intent names an unsupported key location \`${keyLocation}\``,
      );
    }
    return keyMaterial(location.circuitId, location.verifierKeyHash);
  };

  return {
    check: async (preimage, keyLocation) =>
      parseCheckResult(
        await post(
          proofServerUrl,
          "/check",
          createCheckPayload(preimage, (await material(keyLocation))?.ir),
          signal,
        ),
      ),
    prove: async (preimage, keyLocation, overwriteBindingInput) =>
      post(
        proofServerUrl,
        "/prove",
        createProvingPayload(preimage, overwriteBindingInput, await material(keyLocation)),
        signal,
      ),
    lookupKey: (keyLocation) => material(keyLocation),
  };
}

export async function proveTransaction(
  proofServerUrl: string,
  transaction: UnprovenTransaction,
  proofBudgetMs: number,
): Promise<UnboundTransaction> {
  const controller = new AbortController();
  const timeoutError = new PublisherError(
    "proving_timeout",
    `proving exceeded its ${proofBudgetMs} ms budget; no wallet operation started and retry is safe`,
  );
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject(timeoutError);
      controller.abort(timeoutError);
    }, proofBudgetMs);
  });
  try {
    const proving = transaction.prove(
      provingProvider(proofServerUrl, controller.signal),
      CostModel.initialCostModel(),
    );
    return await Promise.race([proving, deadline]);
  } finally {
    clearTimeout(timer);
  }
}
