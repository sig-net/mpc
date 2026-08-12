// `MIDNIGHT_PUB_*` names are the deployment contract; the submit-side variables are
// all-or-none.

import { z } from "zod";

import { NETWORK_IDS } from "@sig-net/midnight-contract-deploy";

export interface Endpoints {
  readonly nodeUrl: string;
  readonly proofServerUrl: string;
  readonly indexerUrl: string;
  readonly indexerWsUrl: string;
}

export interface Config {
  readonly networkId: string;
  readonly endpoints: Endpoints | undefined;
}

const FUNDING_SEED_VAR = "MIDNIGHT_PUB_FUNDING_SEED";

const optionalUrl = (protocols: readonly string[]) =>
  z
    .string()
    .refine(
      (value) => value.length === 0 || (URL.canParse(value) && protocols.includes(new URL(value).protocol)),
      `must be an absolute ${protocols.join(" or ")} URL`,
    )
    .transform((value) => (value.length === 0 ? value : new URL(value).toString()))
    .optional();

const EnvSchema = z.object({
  MIDNIGHT_PUB_NETWORK_ID: z.literal(NETWORK_IDS, `must be one of ${NETWORK_IDS.join(", ")}`),
  MIDNIGHT_PUB_NODE_URL: optionalUrl(["http:", "https:", "ws:", "wss:"]),
  MIDNIGHT_PUB_PROOF_SERVER_URL: optionalUrl(["http:", "https:"]),
  MIDNIGHT_PUB_INDEXER_URL: optionalUrl(["http:", "https:"]),
  MIDNIGHT_PUB_INDEXER_WS_URL: optionalUrl(["ws:", "wss:"]),
  [FUNDING_SEED_VAR]: z.string().optional(),
});

export const SUBMIT_VAR_NAMES = [
  "MIDNIGHT_PUB_NODE_URL",
  "MIDNIGHT_PUB_PROOF_SERVER_URL",
  "MIDNIGHT_PUB_INDEXER_URL",
  "MIDNIGHT_PUB_INDEXER_WS_URL",
  FUNDING_SEED_VAR,
] as const;

function endpointsFromEnv(env: z.infer<typeof EnvSchema>): Endpoints | undefined {
  // Empty counts as absent: the parent sets every variable and blanks the unused ones.
  const missing = SUBMIT_VAR_NAMES.filter((name) => (env[name] ?? "") === "");
  if (missing.length === SUBMIT_VAR_NAMES.length) return undefined;
  if (missing.length > 0) {
    throw new Error(
      `invalid MIDNIGHT_PUB_* configuration: submitting needs all of ${SUBMIT_VAR_NAMES.join(", ")}, ` +
        `or none of them for a deployment that only builds intents; missing ${missing.join(", ")}`,
    );
  }

  return {
    nodeUrl: env.MIDNIGHT_PUB_NODE_URL!,
    proofServerUrl: env.MIDNIGHT_PUB_PROOF_SERVER_URL!,
    indexerUrl: env.MIDNIGHT_PUB_INDEXER_URL!,
    indexerWsUrl: env.MIDNIGHT_PUB_INDEXER_WS_URL!,
  };
}

export function configFromEnv(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    const detail = parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");
    throw new Error(`invalid MIDNIGHT_PUB_* configuration: ${detail}`);
  }

  return {
    networkId: parsed.data.MIDNIGHT_PUB_NETWORK_ID,
    endpoints: endpointsFromEnv(parsed.data),
  };
}

// Read at the point of use: the seed is never carried on `Config`.
export function fundingSeed(): string {
  const seed = process.env[FUNDING_SEED_VAR];
  if (seed === undefined || seed.length === 0) throw new Error(`${FUNDING_SEED_VAR} is required`);
  return seed;
}
