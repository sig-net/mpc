import { describe, expect, it } from "vitest";

import { configFromEnv } from "../src/config.js";

const BUILDER = {
  MIDNIGHT_PUB_NETWORK_ID: "undeployed",
};

const SUBMITTER = {
  ...BUILDER,
  MIDNIGHT_PUB_NODE_URL: "ws://127.0.0.1:9944",
  MIDNIGHT_PUB_PROOF_SERVER_URL: "http://127.0.0.1:6300",
  MIDNIGHT_PUB_INDEXER_URL: "http://127.0.0.1:8088/api/v3/graphql",
  MIDNIGHT_PUB_INDEXER_WS_URL: "ws://127.0.0.1:8088/api/v3/graphql/ws",
  MIDNIGHT_PUB_FUNDING_SEED: "ab".repeat(32),
};

const REQUIRED = [
  "MIDNIGHT_PUB_NODE_URL",
  "MIDNIGHT_PUB_PROOF_SERVER_URL",
  "MIDNIGHT_PUB_INDEXER_URL",
  "MIDNIGHT_PUB_INDEXER_WS_URL",
  "MIDNIGHT_PUB_FUNDING_SEED",
] as const;

describe("configFromEnv", () => {
  it("names every missing variable at once", () => {
    expect(() => configFromEnv(BUILDER)).toThrowError(new RegExp(REQUIRED.join("[\\s\\S]*")));
  });

  it("starts a deployment that submits, with every endpoint canonicalized for the wallet", () => {
    const config = configFromEnv({
      ...SUBMITTER,
      MIDNIGHT_PUB_PROOF_SERVER_URL: "HTTP://127.0.0.1:6300",
    });
    expect(config.endpoints).toEqual({
      nodeUrl: "ws://127.0.0.1:9944/",
      proofServerUrl: "http://127.0.0.1:6300/",
      indexerUrl: "http://127.0.0.1:8088/api/v3/graphql",
      indexerWsUrl: "ws://127.0.0.1:8088/api/v3/graphql/ws",
    });
    expect(config.accountKeys.shieldedSecretKeys.coinPublicKey).toBe(
      "f919eee2f2e7f8423e8deae5c7ea32a69ff685acf93f441841f8dfdea16101ec",
    );
  });

  it("uses the SDK's 16-to-64-byte hex seed contract and never quotes a rejection", () => {
    expect(() =>
      configFromEnv({ ...SUBMITTER, MIDNIGHT_PUB_FUNDING_SEED: "ab".repeat(17) }),
    ).not.toThrow();

    for (const invalid of [
      "",
      "ab".repeat(15),
      "ab".repeat(65),
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    ]) {
      expect(() =>
        configFromEnv({ ...SUBMITTER, MIDNIGHT_PUB_FUNDING_SEED: invalid }),
      ).toThrowError(/MIDNIGHT_PUB_FUNDING_SEED/);
      expect(() =>
        configFromEnv({ ...SUBMITTER, MIDNIGHT_PUB_FUNDING_SEED: invalid }),
      ).not.toThrowError(invalid);
    }
  });

  it("refuses a network id the library does not know and endpoints of the wrong shape", () => {
    expect(() => configFromEnv({ ...SUBMITTER, MIDNIGHT_PUB_NETWORK_ID: "undeploy" })).toThrowError(
      /MIDNIGHT_PUB_NETWORK_ID/,
    );
    for (const name of REQUIRED.slice(0, 4)) {
      for (const value of ["not-a-url", "file:///tmp/socket"]) {
        expect(() => configFromEnv({ ...SUBMITTER, [name]: value }), name).toThrowError(name);
      }
    }
  });
});
