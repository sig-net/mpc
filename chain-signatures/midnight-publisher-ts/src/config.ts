/** `MIDNIGHT_PUB_*` configuration, keeping the Rust implementation's variable names. */

import { z } from "zod";

import { NETWORK_IDS } from "@sig-net/midnight-contract-deploy";

export interface Config {
  readonly port: number;
  /** The loopback boundary IS the access control: no auth, and it holds a funding wallet. */
  readonly bindHost: string;
  /** Substrate ws endpoint. */
  readonly nodeUrl: string;
  /** Mandatory: these contracts are zkir-v3 and cannot be proven locally. */
  readonly proofServerUrl: string;
  /** Where the wallet syncs UTXO and dust state from. */
  readonly indexerUrl: string;
  readonly indexerWsUrl: string;
  /** Root of the compiled-contract assets (`contract/`, `compiler/`, `keys/`, `zkir/`). */
  readonly managedDir: string;
  /** Hot gas-wallet seed. Injected at runtime, never baked into an image. */
  readonly fundingSeed: string;
  readonly networkId: string;
}

function isLoopback(host: string): boolean {
  return ["localhost", "::1", "[::1]"].includes(host) || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

/** Every value is required and taken as given: the operator supplies the full set, nothing is defaulted or derived. */
const EnvSchema = z.object({
  MIDNIGHT_PUB_PORT: z.coerce.number(),
  MIDNIGHT_PUB_BIND_HOST: z.string().min(1),
  MIDNIGHT_PUB_ALLOW_NON_LOOPBACK: z.string().optional(),
  MIDNIGHT_PUB_NODE_URL: z.string().min(1),
  MIDNIGHT_PUB_PROOF_SERVER_URL: z.string().min(1),
  MIDNIGHT_PUB_INDEXER_URL: z.string().min(1),
  MIDNIGHT_PUB_INDEXER_WS_URL: z.string().min(1),
  MIDNIGHT_PUB_MANAGED_DIR: z.string().min(1),
  MIDNIGHT_PUB_FUNDING_SEED: z.string().min(1),
  MIDNIGHT_PUB_NETWORK_ID: z.string().min(1),
});

export function configFromEnv(): Config {
  const parsed = EnvSchema.safeParse(process.env);
  if (!parsed.success) {
    const detail = parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");
    throw new Error(`invalid MIDNIGHT_PUB_* configuration: ${detail}`);
  }
  const env = parsed.data;

  if (!isLoopback(env.MIDNIGHT_PUB_BIND_HOST) && env.MIDNIGHT_PUB_ALLOW_NON_LOOPBACK !== "1") {
    throw new Error(
      `MIDNIGHT_PUB_BIND_HOST=${env.MIDNIGHT_PUB_BIND_HOST} is not a loopback address. This service has no ` +
        `authentication and holds a funding wallet; set MIDNIGHT_PUB_ALLOW_NON_LOOPBACK=1 only ` +
        `when an authenticated boundary fronts it.`,
    );
  }

  // A typo here builds a wallet at a DIFFERENT unshielded address, proves a call,
  // and spends dust, failing only later at the node. The library owns the closed set.
  if (!(NETWORK_IDS as readonly string[]).includes(env.MIDNIGHT_PUB_NETWORK_ID)) {
    throw new Error(`MIDNIGHT_PUB_NETWORK_ID=${env.MIDNIGHT_PUB_NETWORK_ID} is not one of ${NETWORK_IDS.join(", ")}`);
  }

  return {
    port: env.MIDNIGHT_PUB_PORT,
    bindHost: env.MIDNIGHT_PUB_BIND_HOST,
    nodeUrl: env.MIDNIGHT_PUB_NODE_URL,
    proofServerUrl: env.MIDNIGHT_PUB_PROOF_SERVER_URL,
    indexerUrl: env.MIDNIGHT_PUB_INDEXER_URL,
    indexerWsUrl: env.MIDNIGHT_PUB_INDEXER_WS_URL,
    managedDir: env.MIDNIGHT_PUB_MANAGED_DIR,
    fundingSeed: env.MIDNIGHT_PUB_FUNDING_SEED,
    networkId: env.MIDNIGHT_PUB_NETWORK_ID,
  };
}

/** Dependency errors echo values they were handed, and that text becomes a response body. */
export function redact(text: string, values: readonly string[]): string {
  // Load-bearing: `split("")` would explode the text into characters and rejoin
  // it with a placeholder between every one.
  return values.reduce((out, value) => (value ? out.split(value).join("<redacted>") : out), text);
}
