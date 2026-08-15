// `MIDNIGHT_PUB_*` names are the deployment contract. A configured publisher
// always builds and submits, so every wallet endpoint is required at startup.

import { z } from "zod";

import {
  deriveAccountKeys,
  NETWORK_IDS,
  parseSeed,
  SeedFormat,
  type AccountKeys,
  type Endpoints,
  type NetworkId,
} from "@sig-net/midnight-contract-deploy";

export type { Endpoints } from "@sig-net/midnight-contract-deploy";

export interface Config {
  readonly networkId: NetworkId;
  readonly endpoints: Endpoints;
  readonly accountKeys: AccountKeys;
}

const requiredUrl = (protocols: readonly string[]) =>
  z
    .string()
    .min(1)
    .refine(
      (value) => URL.canParse(value) && protocols.includes(new URL(value).protocol),
      `must be an absolute ${protocols.join(" or ")} URL`,
    )
    .transform((value) => new URL(value).toString());

const EnvSchema = z.object({
  MIDNIGHT_PUB_NETWORK_ID: z.literal(NETWORK_IDS, `must be one of ${NETWORK_IDS.join(", ")}`),
  MIDNIGHT_PUB_NODE_URL: requiredUrl(["http:", "https:", "ws:", "wss:"]),
  MIDNIGHT_PUB_PROOF_SERVER_URL: requiredUrl(["http:", "https:"]),
  MIDNIGHT_PUB_INDEXER_URL: requiredUrl(["http:", "https:"]),
  MIDNIGHT_PUB_INDEXER_WS_URL: requiredUrl(["ws:", "wss:"]),
  MIDNIGHT_PUB_FUNDING_SEED: z.string().min(1),
});

function deriveFundingKeys(seed: string, networkId: NetworkId): AccountKeys {
  try {
    const parsed = parseSeed(seed);
    if (parsed.source.format === SeedFormat.Hex) return deriveAccountKeys(seed, networkId);
  } catch {
    // The library describes seed shapes. The deployment error must name the variable
    // without quoting secret input or accepting a mnemonic for an unfunded account.
  }
  throw new Error(
    "MIDNIGHT_PUB_FUNDING_SEED must be hex (16 to 64 bytes); a mnemonic is not accepted",
  );
}

export function configFromEnv(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    const detail = parsed.error.issues
      .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
      .join("; ");
    throw new Error(`invalid MIDNIGHT_PUB_* configuration: ${detail}`);
  }

  const networkId = parsed.data.MIDNIGHT_PUB_NETWORK_ID;
  return {
    networkId,
    endpoints: {
      nodeUrl: parsed.data.MIDNIGHT_PUB_NODE_URL,
      proofServerUrl: parsed.data.MIDNIGHT_PUB_PROOF_SERVER_URL,
      indexerUrl: parsed.data.MIDNIGHT_PUB_INDEXER_URL,
      indexerWsUrl: parsed.data.MIDNIGHT_PUB_INDEXER_WS_URL,
    },
    accountKeys: deriveFundingKeys(parsed.data.MIDNIGHT_PUB_FUNDING_SEED, networkId),
  };
}
