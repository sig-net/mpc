// The proof server holds only the protocol's own keys (`midnight/...`); a contract
// call's prover key, verifier key and IR live in the managed dir and travel in the
// payload. Proving happens before the wallet balances: balancing prices the proof sizes.

import { parseContractKeyLocation } from "@midnight-ntwrk/compact-js";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import { ZKConfigRegistry, zkConfigToProvingKeyMaterial } from "@midnight-ntwrk/midnight-js-types";
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

import { withDeadline } from "./deadline.js";
import { PublisherError } from "./errors.js";
import { RESPOND_CIRCUITS, type RespondCircuit } from "./intent.js";

export type UnboundTransaction = Transaction<SignatureEnabled, Proof, PreBinding>;

const BUILTIN_PREFIX = "midnight/";

function isRespondCircuit(circuitId: string): circuitId is RespondCircuit {
  return RESPOND_CIRCUITS.some((circuit) => circuit === circuitId);
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
  const registry = new ZKConfigRegistry([new NodeZkConfigProvider(signetContractManagedPath)]);
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
    try {
      return zkConfigToProvingKeyMaterial(await registry.get(location));
    } catch (cause) {
      throw new PublisherError(
        "contract_mismatch",
        `the packaged artifacts for circuit \`${location.circuitId}\` do not match the intent or compiler manifest`,
        { cause },
      );
    }
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
  return withDeadline(
    transaction.prove(
      provingProvider(proofServerUrl, controller.signal),
      CostModel.initialCostModel(),
    ),
    proofBudgetMs,
    timeoutError,
    () => controller.abort(timeoutError),
  );
}
