// Shared test scaffolding: the arrange step only.

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Intent } from "@midnightntwrk/ledger-v9";

import type { Config } from "../src/config.js";

export const FIXTURES = fileURLToPath(new URL("./fixtures/", import.meta.url));

export const fixtureBytes = (name: string): Uint8Array => Uint8Array.from(readFileSync(`${FIXTURES}${name}`));

export const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

// The REAL compiled assets, not `FIXTURES`: a circuit run reads `keys/` and `zkir/`,
// so pointing this at the fixture folder fails with a missing-asset error that reads
// like a bug in the builder rather than like a misconfigured test.
export function managedDir(): string {
  const { resolve } = createRequire(import.meta.url);
  return join(dirname(resolve("@sig-net/midnight-contract")), "managed");
}

// No endpoints, which is what makes it safe to run: the submit path can only reach a
// wallet a test primed by hand. Anything that forgets to prime one answers rather than
// dialling an address.
export const testConfig = (overrides: Partial<Config> = {}): Config => ({
  managedDir: managedDir(),
  networkId: "undeployed",
  endpoints: undefined,
  ...overrides,
});

// The markers are the literal instance tags, not classes.
export const decodeIntent = (bytes: Uint8Array) => Intent.deserialize("signature", "pre-proof", "pre-binding", bytes);

export const renderCall = (bytes: Uint8Array): string => String(decodeIntent(bytes).actions[0]);

/**
 * The circuit's arguments as the transcript pushed them: one `pushs` op whose tuple IS
 * the event struct, in the order the contract declared it, tagged with each field's
 * width. It is the only place the argument VALUES survive into the intent, so it is the
 * only thing that can tell a correct call from one whose fields were transposed,
 * dropped or zeroed. Both circuits end in the signature's `b32b32b32b1`, which is what
 * distinguishes this op from the transcript's other pushes.
 *
 * Byte goldens cannot do this job: `buildIntent` samples a fresh communication
 * commitment per call, so the bytes differ every time and only the decode is stable.
 */
export function pushedCallArgs(bytes: Uint8Array): string {
  const ops = renderCall(bytes)
    .split("\n")
    .map((line) => line.trim().replace(/,$/, ""))
    .filter((op) => op.startsWith("pushs <[") && op.endsWith("b32b32b32b1>"));

  if (ops.length !== 1) throw new Error(`expected one argument push in the transcript, found ${ops.length}`);
  return ops[0]!;
}
