// The entry point, as the Rust client will actually run it: a real `node dist/main.js`
// on a real pipe. The two invariants the whole design rests on, stdout carries nothing
// but reply lines and requests are answered one at a time, live in `main.ts` and are
// unreachable from `handleLine`, so nothing else can pin them.

import { execFileSync } from "node:child_process";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";

import { LedgerParameters } from "@midnightntwrk/ledger-v9";

import { initialSingletonStateHex, managedDir, toHex } from "./support.js";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const ENTRY = `${ROOT}dist/main.js`;

const CONTRACT_STATE = await initialSingletonStateHex();

const SINGLETON = "d7b3c45da613be25050bbdf3fde4cef8f66154d3a52ca8c1edd878bd6391f169";
const REQUEST_ID = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";

// Five is enough to expose an out-of-order reply and cheap enough to spend a circuit
// run on each. They go down the pipe in one burst, before the child answers any.
const BURST = 5;

const request = (id: number): string =>
  JSON.stringify({
    id,
    circuit: "respond",
    contractAddress: SINGLETON,
    requestId: REQUEST_ID,
    signature: { bigR: { x: "11".repeat(32), y: "22".repeat(32) }, s: "33".repeat(32), recoveryId: 0 },
    contractState: CONTRACT_STATE,
    ledgerParameters: toHex(LedgerParameters.initialParameters().serialize()),
    coinPublicKey: "44".repeat(32),
    ttlSeconds: 1_800_000_000,
  });

interface Run {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function drive(lines: readonly string[]): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [ENTRY], {
      env: { ...process.env, MIDNIGHT_PUB_MANAGED_DIR: managedDir(), MIDNIGHT_PUB_NETWORK_ID: "undeployed" },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => (stdout += chunk));
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));

    for (const line of lines) child.stdin.write(`${line}\n`);
    child.stdin.end();
  });
}

// Built here rather than assumed present, so the suite can never pass by testing a
// stale `dist/` or by quietly skipping.
beforeAll(() => {
  const { resolve } = createRequire(import.meta.url);
  execFileSync(process.execPath, [resolve("typescript/bin/tsc"), "-p", `${ROOT}tsconfig.build.json`], {
    cwd: ROOT,
    stdio: "pipe",
  });
}, 180_000);

describe("dist/main.js over a pipe", () => {
  it("answers a burst in order, one line per request, and nothing else on stdout", async () => {
    const run = await drive([...Array.from({ length: BURST }, (_, index) => request(index + 1)), "", "{not json"]);

    expect(run.code).toBe(0);

    // Every stdout line parses. A stray `console.log` anywhere in `src/` breaks this
    // before it breaks anything subtler, which is the point.
    const replies = run.stdout.split("\n").filter((line) => line.length > 0).map((line) => JSON.parse(line));

    // The blank line is skipped, the bad line is answered: BURST + 1.
    expect(replies).toHaveLength(BURST + 1);
    // Order, not just presence: replies are matched by position downstream and a
    // concurrent read would let a fast request overtake a slow one.
    expect(replies.map((reply) => reply.id)).toEqual([...Array.from({ length: BURST }, (_, i) => i + 1), null]);
    expect(replies.slice(0, BURST).every((reply) => reply.ok === true)).toBe(true);
    expect(replies.slice(0, BURST).every((reply) => /^(?:[0-9a-f]{2})+$/.test(reply.intent))).toBe(true);
    expect(replies.at(-1)).toMatchObject({ ok: false, code: "bad_request" });
  }, 120_000);

  it("answers a submit on a build-only deployment instead of dying on it", async () => {
    // `drive` configures no wallet, which is the indexer-only deployment: it builds
    // intents and cannot pay for one. The child must stay in step with its reader
    // anyway, one line in and one line out, and keep answering afterwards. Exiting
    // would cost the caller the next request too, because a dead child is a respawn
    // and a retry on its side.
    const built = JSON.parse((await drive([request(1)])).stdout.trim()) as { intent: string };

    const run = await drive([
      JSON.stringify({ id: 1, op: "submit", intent: built.intent }),
      JSON.stringify({ id: 2, op: "nonsense" }),
      request(3),
    ]);

    expect(run.code).toBe(0);
    const replies = run.stdout.split("\n").filter((line) => line.length > 0).map((line) => JSON.parse(line));
    expect(replies.map((reply) => reply.id)).toEqual([1, 2, 3]);
    expect(replies[0]).toMatchObject({ ok: false, code: "wallet_unsynced" });
    expect(replies[1]).toMatchObject({ ok: false, code: "bad_request" });
    expect(replies[2]).toMatchObject({ ok: true });
  }, 120_000);

  it("keeps every diagnostic off the wire", async () => {
    // The startup line and any failure evidence go to stderr. A reply appearing there
    // instead would mean stdout and the log had been swapped somewhere.
    const run = await drive([request(1), JSON.stringify({ id: 2, circuit: "respond" })]);

    expect(run.stderr.length).toBeGreaterThan(0);
    const strayReplies = run.stderr
      .split("\n")
      .filter((line) => line.trim().startsWith("{"))
      .filter((line) => {
        try {
          return "ok" in JSON.parse(line);
        } catch {
          return false;
        }
      });

    expect(strayReplies).toEqual([]);
    expect(run.stdout.split("\n").filter((line) => line.length > 0)).toHaveLength(2);
  }, 120_000);
});
