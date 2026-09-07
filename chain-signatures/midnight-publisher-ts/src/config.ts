// Rust owns and validates publisher configuration. This module only turns the
// parent-set process values into the SDK-facing runtime config.

import {
  deriveAccountKeys,
  type AccountKeys,
  type MidnightNodeConfig,
  type NetworkId,
} from "@sig-net/midnight-contract-deploy";

export interface Config {
  readonly node: MidnightNodeConfig;
  readonly accountKeys: AccountKeys;
}

export function configFromEnv(env: NodeJS.ProcessEnv = process.env): Config {
  const networkId = env.MIDNIGHT_PUB_NETWORK_ID as NetworkId;
  return {
    node: {
      networkId,
      nodeUrl: env.MIDNIGHT_PUB_NODE_URL!,
      proofServerUrl: env.MIDNIGHT_PUB_PROOF_SERVER_URL!,
      indexerUrl: env.MIDNIGHT_PUB_INDEXER_URL!,
      indexerWsUrl: env.MIDNIGHT_PUB_INDEXER_WS_URL!,
    },
    accountKeys: deriveAccountKeys(env.MIDNIGHT_PUB_FUNDING_SEED!, networkId),
  };
}
