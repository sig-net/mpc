// What `src/` is allowed to hold: the funding seed is read in exactly one place and
// never carried on a value anything else renders.

import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { configFromEnv } from "../src/config.js";
import { parseFundingSeed } from "../src/wallet.js";
import { managedDir } from "./support.js";

const SRC = fileURLToPath(new URL("../src/", import.meta.url));

const SEED_VAR = "MIDNIGHT_PUB_FUNDING_SEED";

// Distinctive enough that a substring of it appearing anywhere is the seed, and a real
// 32-byte hex seed so nothing rejects it for its shape.
const SEED = "c0ffee1234567890c0ffee1234567890c0ffee1234567890c0ffee1234567890";

const sources = async (): Promise<string[]> => (await readdir(SRC, { recursive: true })).filter((f) => f.endsWith(".ts"));

describe("the devtools quarantine", () => {
  it("the shipped code never reaches the deploy wallet", async () => {
    // `tsconfig.build.json` emits `src/` alone, so an import would pull an unshipped
    // file into `dist/`.
    const files = await sources();

    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      expect(await readFile(`${SRC}${file}`, "utf8"), file).not.toMatch(/devtools/);
    }
  });
});

describe("the funding seed", () => {
  it("is read from the environment in exactly one file", async () => {
    // A second file reaching into `process.env` would read the seed behind the one
    // reader's back, and nothing would notice.
    const reading: string[] = [];
    for (const file of await sources()) {
      if ((await readFile(`${SRC}${file}`, "utf8")).includes("process.env")) reading.push(file);
    }

    expect(reading).toEqual(["config.ts"]);
  });

  it("is never carried on the config, so nothing that renders one renders it", () => {
    const config = configFromEnv({
      MIDNIGHT_PUB_MANAGED_DIR: managedDir(),
      MIDNIGHT_PUB_NETWORK_ID: "undeployed",
      MIDNIGHT_PUB_NODE_URL: "ws://127.0.0.1:9944",
      MIDNIGHT_PUB_PROOF_SERVER_URL: "http://127.0.0.1:6300",
      MIDNIGHT_PUB_INDEXER_URL: "http://127.0.0.1:8088/api/v3/graphql",
      MIDNIGHT_PUB_INDEXER_WS_URL: "ws://127.0.0.1:8088/api/v3/graphql/ws",
      [SEED_VAR]: SEED,
    });

    expect(JSON.stringify(config)).not.toContain(SEED);
    expect(config.endpoints).toBeDefined();
  });

  it("is never quoted by the parser that rejects it", () => {
    const tooLong = SEED.repeat(3);

    expect(() => parseFundingSeed(tooLong)).toThrowError(/MIDNIGHT_PUB_FUNDING_SEED/);
    expect(() => parseFundingSeed(tooLong)).not.toThrowError(SEED);
  });
});
