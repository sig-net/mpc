import { describe, expect, it } from "vitest";

import { configFromEnv, SUBMIT_VAR_NAMES } from "../src/config.js";

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

describe("configFromEnv", () => {
  it("starts a deployment that only builds intents", () => {
    expect(configFromEnv(BUILDER)).toEqual({
      networkId: "undeployed",
      endpoints: undefined,
    });
  });

  it("starts a deployment that submits, with every endpoint the wallet needs", () => {
    const config = configFromEnv(SUBMITTER);
    expect(config.endpoints).toEqual({
      nodeUrl: "ws://127.0.0.1:9944/",
      proofServerUrl: "http://127.0.0.1:6300/",
      indexerUrl: "http://127.0.0.1:8088/api/v3/graphql",
      indexerWsUrl: "ws://127.0.0.1:8088/api/v3/graphql/ws",
    });
    expect(JSON.stringify(config)).not.toContain(SUBMITTER.MIDNIGHT_PUB_FUNDING_SEED);
  });

  it("reads a blank seed as no wallet, because the parent always sets the variable", () => {
    expect(configFromEnv({ ...BUILDER, MIDNIGHT_PUB_FUNDING_SEED: "" }).endpoints).toBeUndefined();
  });

  it("refuses a half-configured submit path at startup, naming what is missing", () => {
    // Left to the first request, a typo'd endpoint costs a real signature instead of a restart.
    for (const name of SUBMIT_VAR_NAMES) {
      const partial: Record<string, string> = { ...SUBMITTER };
      delete partial[name];

      expect(() => configFromEnv(partial), name).toThrowError(name);
    }
  });

  it("names every missing variable at once, not just the first", () => {
    expect(() => configFromEnv({ ...BUILDER, MIDNIGHT_PUB_NODE_URL: "ws://127.0.0.1:9944" })).toThrowError(
      /MIDNIGHT_PUB_PROOF_SERVER_URL[\s\S]*MIDNIGHT_PUB_INDEXER_URL/,
    );
  });

  it("refuses a network id the library does not know", () => {
    expect(() => configFromEnv({ ...BUILDER, MIDNIGHT_PUB_NETWORK_ID: "undeploy" })).toThrowError(
      /MIDNIGHT_PUB_NETWORK_ID/,
    );
  });

  it("refuses malformed endpoint URLs at startup", () => {
    for (const name of SUBMIT_VAR_NAMES.slice(0, 4)) {
      expect(() => configFromEnv({ ...SUBMITTER, [name]: "not-a-url" }), name).toThrowError(name);
    }
  });

  it("refuses unsupported endpoint schemes at startup", () => {
    for (const name of SUBMIT_VAR_NAMES.slice(0, 4)) {
      expect(() => configFromEnv({ ...SUBMITTER, [name]: "file:///tmp/socket" }), name).toThrowError(name);
    }
  });

  it("canonicalizes endpoint schemes before passing them to the wallet SDK", () => {
    const config = configFromEnv({ ...SUBMITTER, MIDNIGHT_PUB_NODE_URL: "HTTP://127.0.0.1:9944" });

    expect(config.endpoints?.nodeUrl).toBe("http://127.0.0.1:9944/");
  });
});
