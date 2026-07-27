// `MIDNIGHT_PUB_*` configuration. The variable names are the deployment contract; never rename casually.

import { z } from "zod";

import { NETWORK_IDS } from "@sig-net/midnight-contract-deploy";

export interface Config {
  readonly port: number;
  // The loopback boundary IS the access control: no auth, and it holds a funding wallet.
  readonly bindHost: string;
  readonly nodeUrl: string;
  // Mandatory: these contracts are zkir-v3 and cannot be proven locally.
  readonly proofServerUrl: string;
  readonly indexerUrl: string;
  readonly indexerWsUrl: string;
  // Root of the compiled-contract assets (`contract/`, `compiler/`, `keys/`, `zkir/`).
  readonly managedDir: string;
  readonly networkId: string;
}

function isLoopback(host: string): boolean {
  return ["localhost", "::1", "[::1]"].includes(host) || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

// Every value is required: the operator supplies the full set, nothing is defaulted.
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
  // A typo here builds a wallet at a DIFFERENT unshielded address, proves a call,
  // and spends dust, failing only later at the node. The library owns the closed set.
  MIDNIGHT_PUB_NETWORK_ID: z.literal(NETWORK_IDS, `must be one of ${NETWORK_IDS.join(", ")}`),
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

  return {
    port: env.MIDNIGHT_PUB_PORT,
    bindHost: env.MIDNIGHT_PUB_BIND_HOST,
    nodeUrl: env.MIDNIGHT_PUB_NODE_URL,
    proofServerUrl: env.MIDNIGHT_PUB_PROOF_SERVER_URL,
    indexerUrl: env.MIDNIGHT_PUB_INDEXER_URL,
    indexerWsUrl: env.MIDNIGHT_PUB_INDEXER_WS_URL,
    managedDir: env.MIDNIGHT_PUB_MANAGED_DIR,
    networkId: env.MIDNIGHT_PUB_NETWORK_ID,
  };
}

const FUNDING_SEED_VAR = "MIDNIGHT_PUB_FUNDING_SEED" satisfies keyof z.infer<typeof EnvSchema>;

// Read at the point of use; `EnvSchema` requires it, so a missing one fails at boot.
export function fundingSeed(): string {
  const seed = process.env[FUNDING_SEED_VAR];
  if (seed === undefined || seed.length === 0) throw new Error(`${FUNDING_SEED_VAR} is required`);
  return seed;
}
