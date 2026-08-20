import { describe, expect, it } from "vitest";

import { configFromEnv } from "../src/config.js";

const SUBMITTER: NodeJS.ProcessEnv = {
  MIDNIGHT_PUB_NETWORK_ID: "undeployed",
  MIDNIGHT_PUB_NODE_URL: "ws://127.0.0.1:9944",
  MIDNIGHT_PUB_PROOF_SERVER_URL: "http://127.0.0.1:6300",
  MIDNIGHT_PUB_INDEXER_URL: "http://127.0.0.1:8088/api/v3/graphql",
  MIDNIGHT_PUB_INDEXER_WS_URL: "ws://127.0.0.1:8088/api/v3/graphql/ws",
  MIDNIGHT_PUB_FUNDING_SEED: "ab".repeat(32),
};

describe("configFromEnv", () => {
  it("turns the parent-set process values into the SDK config", () => {
    const config = configFromEnv(SUBMITTER);
    expect(config.endpoints).toEqual({
      nodeUrl: "ws://127.0.0.1:9944",
      proofServerUrl: "http://127.0.0.1:6300",
      indexerUrl: "http://127.0.0.1:8088/api/v3/graphql",
      indexerWsUrl: "ws://127.0.0.1:8088/api/v3/graphql/ws",
    });
    expect(config.accountKeys.shieldedSecretKeys.coinPublicKey).toBe(
      "f919eee2f2e7f8423e8deae5c7ea32a69ff685acf93f441841f8dfdea16101ec",
    );
  });

  it("retains derived keys rather than the seed", () => {
    const config = configFromEnv(SUBMITTER);
    expect(JSON.stringify(config)).not.toContain(SUBMITTER.MIDNIGHT_PUB_FUNDING_SEED);
  });
});
