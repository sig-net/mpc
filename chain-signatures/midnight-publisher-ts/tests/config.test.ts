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
  it("refuses a deployment without the wallet configuration", () => {
    expect(() => configFromEnv(BUILDER)).toThrowError(
      /MIDNIGHT_PUB_NODE_URL[\s\S]*MIDNIGHT_PUB_FUNDING_SEED/,
    );
  });

  it("starts a deployment that submits, with every endpoint the wallet needs", () => {
    const config = configFromEnv(SUBMITTER);
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

  it("refuses a blank funding seed", () => {
    expect(() => configFromEnv({ ...SUBMITTER, MIDNIGHT_PUB_FUNDING_SEED: "" })).toThrowError(
      /MIDNIGHT_PUB_FUNDING_SEED/,
    );
  });

  it("uses the SDK's 16-to-64-byte hex seed contract and never quotes a rejection", () => {
    expect(() =>
      configFromEnv({ ...SUBMITTER, MIDNIGHT_PUB_FUNDING_SEED: "ab".repeat(17) }),
    ).not.toThrow();

    for (const invalid of [
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

  it("refuses a half-configured submit path at startup, naming what is missing", () => {
    // Left to the first request, a typo'd endpoint costs a real signature instead of a restart.
    for (const name of REQUIRED) {
      const partial: Record<string, string> = { ...SUBMITTER };
      delete partial[name];

      expect(() => configFromEnv(partial), name).toThrowError(name);
    }
  });

  it("names every missing variable at once, not just the first", () => {
    expect(() =>
      configFromEnv({ ...BUILDER, MIDNIGHT_PUB_NODE_URL: "ws://127.0.0.1:9944" }),
    ).toThrowError(/MIDNIGHT_PUB_PROOF_SERVER_URL[\s\S]*MIDNIGHT_PUB_INDEXER_URL/);
  });

  it("refuses a network id the library does not know", () => {
    expect(() => configFromEnv({ ...BUILDER, MIDNIGHT_PUB_NETWORK_ID: "undeploy" })).toThrowError(
      /MIDNIGHT_PUB_NETWORK_ID/,
    );
  });

  it("refuses malformed endpoint URLs at startup", () => {
    for (const name of REQUIRED.slice(0, 4)) {
      expect(() => configFromEnv({ ...SUBMITTER, [name]: "not-a-url" }), name).toThrowError(name);
    }
  });

  it("refuses unsupported endpoint schemes at startup", () => {
    for (const name of REQUIRED.slice(0, 4)) {
      expect(
        () => configFromEnv({ ...SUBMITTER, [name]: "file:///tmp/socket" }),
        name,
      ).toThrowError(name);
    }
  });

  it("canonicalizes endpoint schemes before passing them to the wallet SDK", () => {
    const config = configFromEnv({ ...SUBMITTER, MIDNIGHT_PUB_NODE_URL: "HTTP://127.0.0.1:9944" });

    expect(config.endpoints?.nodeUrl).toBe("http://127.0.0.1:9944/");
  });
});
