// `MIDNIGHT_PUB_*`, which is the deployment contract. Two deployments are legitimate,
// and telling them apart is this file's whole subject: one that only builds intents,
// and one that also pays for them.

import { describe, expect, it } from "vitest";

import { configFromEnv, SUBMIT_VAR_NAMES } from "../src/config.js";

const BUILDER = {
  MIDNIGHT_PUB_MANAGED_DIR: "/managed",
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
    // The indexer-only node. It never submits, is never given a credential, and must
    // still come up: refusing here would take the read path down with the write path.
    expect(configFromEnv(BUILDER)).toEqual({
      managedDir: "/managed",
      networkId: "undeployed",
      endpoints: undefined,
    });
  });

  it("starts a deployment that submits, with every endpoint the wallet needs", () => {
    expect(configFromEnv(SUBMITTER).endpoints).toEqual({
      nodeUrl: "ws://127.0.0.1:9944",
      proofServerUrl: "http://127.0.0.1:6300",
      indexerUrl: "http://127.0.0.1:8088/api/v3/graphql",
      indexerWsUrl: "ws://127.0.0.1:8088/api/v3/graphql/ws",
    });
  });

  it("reads a blank seed as no wallet, because the parent always sets the variable", () => {
    // The spawning node writes every `MIDNIGHT_PUB_*` name it knows and blanks the ones
    // its deployment does not use, so absent and empty have to mean the same thing.
    expect(configFromEnv({ ...BUILDER, MIDNIGHT_PUB_FUNDING_SEED: "" }).endpoints).toBeUndefined();
  });

  it("refuses a half-configured submit path at startup, naming what is missing", () => {
    // The failure worth having. Left to the first request, a typo'd endpoint costs a
    // real signature instead of a restart, and the request is not the thing at fault.
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
    // A typo here derives a DIFFERENT unshielded address, proves a call and spends dust,
    // failing only later at the node.
    expect(() => configFromEnv({ ...BUILDER, MIDNIGHT_PUB_NETWORK_ID: "undeploy" })).toThrowError(
      /MIDNIGHT_PUB_NETWORK_ID/,
    );
  });

  it("refuses a missing managed dir, which both operations need", () => {
    expect(() => configFromEnv({ MIDNIGHT_PUB_NETWORK_ID: "undeployed" })).toThrowError(/MIDNIGHT_PUB_MANAGED_DIR/);
  });
});
