import { describe, expect, it } from "vitest";

import { configFromEnv } from "../src/config.js";
import { PUBLISHER_ENV } from "./support.js";

describe("configFromEnv", () => {
  it("turns the parent-set process values into the SDK config", () => {
    const config = configFromEnv(PUBLISHER_ENV);
    expect(config.node).toEqual({
      networkId: "undeployed",
      nodeUrl: "http://127.0.0.1:9944",
      proofServerUrl: "http://127.0.0.1:6300",
      indexerUrl: "http://127.0.0.1:8088/api/v3/graphql",
      indexerWsUrl: "ws://127.0.0.1:8088/api/v3/graphql/ws",
    });
    expect(config.accountKeys.shieldedSecretKeys.coinPublicKey).toBe(
      "f919eee2f2e7f8423e8deae5c7ea32a69ff685acf93f441841f8dfdea16101ec",
    );
  });

  it("retains derived keys rather than the seed", () => {
    const config = configFromEnv(PUBLISHER_ENV);
    expect(JSON.stringify(config)).not.toContain(PUBLISHER_ENV.MIDNIGHT_PUB_FUNDING_SEED);
  });
});
