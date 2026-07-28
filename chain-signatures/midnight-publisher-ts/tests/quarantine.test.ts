// What `src/` is allowed to hold, and what may never leave it.
//
// This file used to assert that nothing under `src/` read a funding seed at all. That
// property is deliberately gone: paying a Midnight fee needs spendable DUST, DUST is
// derived by replaying every block's ledger events from genesis, and only the wallet
// SDK does that. The wallet is back here, so the seed is back here, legitimately.
//
// What replaces it is the property that actually protects the seed now. It is read in
// exactly one place, it is never carried on a value anything else renders, and it
// cannot reach a reply line or an error message: this process writes its replies to
// stdout, and stdout is the parent node's stdin, so a seed on it would be a seed in
// that node's log.

import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { LedgerParameters } from "@midnightntwrk/ledger-v9";

import { configFromEnv, fundingSeed, redactSeed } from "../src/config.js";
import { buildIntent } from "../src/intent.js";
import { handleLine } from "../src/protocol.js";
import { closePublisher, primePublisher } from "../src/submit.js";
import { parseFundingSeed } from "../src/wallet.js";
import { fixtureBytes, managedDir, testConfig, toHex } from "./support.js";

const SRC = fileURLToPath(new URL("../src/", import.meta.url));

const SEED_VAR = "MIDNIGHT_PUB_FUNDING_SEED";

// Distinctive enough that a substring of it appearing anywhere is the seed and not a
// coincidence, and a real 32-byte hex seed so nothing rejects it for its shape.
const SEED = "c0ffee1234567890c0ffee1234567890c0ffee1234567890c0ffee1234567890";

const sources = async (): Promise<string[]> => (await readdir(SRC, { recursive: true })).filter((f) => f.endsWith(".ts"));

describe("the devtools quarantine", () => {
  it("the shipped code never reaches the deploy wallet", async () => {
    // `devtools/` holds the deploy path and its own seed handling, and nothing under
    // `src/` may import it: `tsconfig.build.json` emits `src/` alone, so an import would
    // pull an unshipped file into `dist/`.
    const files = await sources();

    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      expect(await readFile(`${SRC}${file}`, "utf8"), file).not.toMatch(/devtools/);
    }
  });
});

describe("the funding seed", () => {
  it("is read from the environment in exactly one file", async () => {
    // Not style. One reader is what makes the redaction below total: a second file
    // reaching into `process.env` would bypass it and nothing would notice. The check
    // is on the environment rather than on the variable's name, because naming it in a
    // message is fine and reading it behind the redaction's back is not.
    const reading: string[] = [];
    for (const file of await sources()) {
      if ((await readFile(`${SRC}${file}`, "utf8")).includes("process.env")) reading.push(file);
    }

    expect(reading).toEqual(["config.ts"]);
  });

  it("is never carried on the config, so nothing that renders one renders it", () => {
    // The whole config is fair game for a startup log line. The seed is read at the
    // point of use precisely so it is not in this object.
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
    // The one place that inspects the value itself, and 96 bytes is past the range it
    // accepts. Its message names the variable and never the value.
    const tooLong = SEED.repeat(3);

    expect(() => parseFundingSeed(tooLong)).toThrowError(/MIDNIGHT_PUB_FUNDING_SEED/);
    expect(() => parseFundingSeed(tooLong)).not.toThrowError(SEED);
  });
});

describe("redactSeed", () => {
  beforeEach(() => {
    process.env[SEED_VAR] = SEED;
  });

  afterEach(() => {
    delete process.env[SEED_VAR];
  });

  it("blanks the seed in every spelling the seed parser accepts", () => {
    // `parseSeed` takes a `0x` prefix and either case, and normalizes to bare lowercase
    // hex, so a dependency may quote back the operator's spelling or the normalized one.
    // Each is checked against ITSELF: comparing every case against the lowercase form
    // would pass vacuously for the uppercase one.
    for (const spelling of [SEED, `0x${SEED}`, SEED.toUpperCase()]) {
      const redacted = redactSeed(`derivation failed for ${spelling}`);

      expect(redacted, spelling).not.toContain(spelling.replace(/^0x/, ""));
      expect(redacted, spelling).toContain("[redacted]");
    }
  });

  it("leaves everything else alone", () => {
    expect(redactSeed("balance failed: could not balance dust")).toBe("balance failed: could not balance dust");
  });

  it("does nothing when the seed is too short to be one", () => {
    // A blank or stub value would otherwise match everywhere and redact whole messages.
    process.env[SEED_VAR] = "ab";
    expect(redactSeed("a message about ab and other things")).toBe("a message about ab and other things");
  });
});

describe("a reply line", () => {
  // A real intent, because the seed can only reach a reply from past the point where a
  // submit is accepted: a malformed one is refused before any wallet is consulted.
  let intent: string;

  beforeAll(async () => {
    intent = toHex(
      await buildIntent(managedDir(), {
        circuit: "respond",
        contractAddress: "d7b3c45da613be25050bbdf3fde4cef8f66154d3a52ca8c1edd878bd6391f169",
        requestId: "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48",
        signature: { bigR: { x: "11".repeat(32), y: "22".repeat(32) }, s: "33".repeat(32), recoveryId: 0 },
        contractState: toHex(fixtureBytes("respond-singleton-state-37571.mn")),
        ledgerParameters: toHex(LedgerParameters.initialParameters().serialize()),
        coinPublicKey: "44".repeat(32),
        ttlSeconds: 1_800_000_000,
      }),
    );
  }, 120_000);

  afterEach(async () => {
    await closePublisher();
    delete process.env[SEED_VAR];
  });

  it("cannot carry the seed, even when a dependency puts it in the failure", async () => {
    // The failure mode this exists for: a library that quotes its own input. Its text
    // reaches `message` verbatim, so without the redaction the seed is on the wire, and
    // this process's stdout is the parent node's stdin.
    process.env[SEED_VAR] = SEED;
    expect(fundingSeed()).toBe(SEED);

    primePublisher(Promise.reject(new Error(`cannot derive keys from seed ${SEED}`)));

    const line = await handleLine(testConfig(), JSON.stringify({ id: 1, op: "submit", intent }));

    expect(line).not.toContain(SEED);
    expect(line).toContain("[redacted]");
    expect(JSON.parse(line)).toMatchObject({ id: 1, ok: false, code: "wallet_unsynced" });
  });
});
