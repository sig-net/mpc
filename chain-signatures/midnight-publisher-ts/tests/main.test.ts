// The entry point as the Rust client runs it: a real `node dist/main.js` on a real
// pipe. The two invariants that live only in `main.ts`, stdout carries nothing but
// reply lines and requests are answered one at a time, are unreachable from `handleLine`.

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { respondInput } from "./support.js";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const ENTRY = `${ROOT}dist/main.js`;

const BURST = 2;
const BUILD = await respondInput();

const request = (id: number): string =>
  JSON.stringify({
    id,
    ...BUILD,
  });

interface Run {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function drive(lines: readonly string[], env: NodeJS.ProcessEnv = {}): Promise<Run> {
  return new Promise((resolve, reject) => {
    const childEnv = { ...process.env };
    for (const name of Object.keys(childEnv)) {
      if (name.startsWith("MIDNIGHT_PUB_")) delete childEnv[name];
    }
    const child = spawn(process.execPath, [ENTRY], {
      env: {
        ...childEnv,
        MIDNIGHT_PUB_NETWORK_ID: "undeployed",
        MIDNIGHT_PUB_NODE_URL: "ws://127.0.0.1:9944",
        MIDNIGHT_PUB_PROOF_SERVER_URL: "http://127.0.0.1:6300",
        MIDNIGHT_PUB_INDEXER_URL: "http://127.0.0.1:8088/api/v3/graphql",
        MIDNIGHT_PUB_INDEXER_WS_URL: "ws://127.0.0.1:8088/api/v3/graphql/ws",
        MIDNIGHT_PUB_FUNDING_SEED: "ab".repeat(32),
        ...env,
      },
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

describe("dist/main.js over a pipe", () => {
  it("answers a burst in order, one line per request, and nothing else on stdout", async () => {
    const run = await drive([...Array.from({ length: BURST }, (_, index) => request(index + 1)), "", "{not json"]);

    expect(run.code).toBe(0);

    expect(run.stdout.endsWith("\n")).toBe(true);
    const replyLines = run.stdout.slice(0, -1).split("\n");
    expect(replyLines.every((line) => line.length > 0)).toBe(true);
    const replies = replyLines.map((line) => JSON.parse(line));

    // The blank line is skipped, the bad line is answered: BURST + 1.
    expect(replies).toHaveLength(BURST + 1);
    // Order, not just presence: replies are matched by position downstream.
    expect(replies.map((reply) => reply.id)).toEqual([...Array.from({ length: BURST }, (_, i) => i + 1), null]);
    expect(replies.slice(0, BURST).every((reply) => reply.ok === true)).toBe(true);
    expect(replies.slice(0, BURST).every((reply) => /^(?:[0-9a-f]{2})+$/.test(reply.intent))).toBe(true);
    expect(replies.at(-1)).toMatchObject({ ok: false, code: "bad_request" });
  }, 120_000);

  it("does not print credentials carried by the node URL", async () => {
    const run = await drive([], {
      MIDNIGHT_PUB_NODE_URL: "https://authuser:secret@example.invalid/rpc?token=private",
      MIDNIGHT_PUB_PROOF_SERVER_URL: "http://127.0.0.1:6300",
      MIDNIGHT_PUB_INDEXER_URL: "http://127.0.0.1:8088/api/v3/graphql",
      MIDNIGHT_PUB_INDEXER_WS_URL: "ws://127.0.0.1:8088/api/v3/graphql/ws",
      MIDNIGHT_PUB_FUNDING_SEED: "ab".repeat(32),
    });

    expect(run.code).toBe(0);
    expect(run.stderr).toContain("node=https://example.invalid");
    expect(run.stderr).not.toContain("authuser");
    expect(run.stderr).not.toContain("secret");
    expect(run.stderr).not.toContain("private");
  });
});
