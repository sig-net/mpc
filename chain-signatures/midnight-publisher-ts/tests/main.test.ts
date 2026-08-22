// The entry point as the Rust client runs it: a real `node dist/main.js` on a real
// pipe. The two invariants that live only in `main.ts`, stdout carries nothing but
// reply lines and requests are answered one at a time, are unreachable from `handleLine`.

import { spawn } from "node:child_process";
import { createServer, type Socket } from "node:net";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { respondInput } from "./support.js";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const ENTRY = `${ROOT}dist/main.js`;

const BURST = 2;
const CHILD_PROCESS_TIMEOUT_MS = 30_000;
const BUILD = await respondInput();

const STARTUP_ENV: NodeJS.ProcessEnv = {
  MIDNIGHT_PUB_NETWORK_ID: "undeployed",
  MIDNIGHT_PUB_NODE_URL: "ws://127.0.0.1:9944",
  MIDNIGHT_PUB_PROOF_SERVER_URL: "http://127.0.0.1:6300",
  MIDNIGHT_PUB_INDEXER_URL: "http://127.0.0.1:8088/api/v3/graphql",
  MIDNIGHT_PUB_INDEXER_WS_URL: "ws://127.0.0.1:8088/api/v3/graphql/ws",
  MIDNIGHT_PUB_FUNDING_SEED: "ab".repeat(32),
};

const ready = (): string => JSON.stringify({ id: 0, op: "ready", protocolVersion: 1 });

const envFor = (port: number): NodeJS.ProcessEnv => ({
  ...STARTUP_ENV,
  MIDNIGHT_PUB_NODE_URL: `ws://127.0.0.1:${port}`,
  MIDNIGHT_PUB_PROOF_SERVER_URL: `http://127.0.0.1:${port}`,
  MIDNIGHT_PUB_INDEXER_URL: `http://127.0.0.1:${port}/api/v3/graphql`,
  MIDNIGHT_PUB_INDEXER_WS_URL: `ws://127.0.0.1:${port}/api/v3/graphql/ws`,
});

const request = (id: number): string =>
  JSON.stringify({
    id,
    op: "build",
    ...BUILD,
  });

interface Run {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
}

function drive(
  lines: readonly string[],
  env: NodeJS.ProcessEnv = {},
  watchdogMs?: number,
): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [ENTRY], {
      env: {
        ...process.env,
        ...env,
      },
    });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const watchdog =
      watchdogMs === undefined
        ? undefined
        : setTimeout(() => {
            timedOut = true;
            child.kill("SIGKILL");
          }, watchdogMs);
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => (stdout += chunk));
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(watchdog);
      resolve({ code, stdout, stderr, timedOut });
    });

    for (const line of lines) child.stdin.write(`${line}\n`);
    child.stdin.end();
  });
}

async function openBlackHole(): Promise<{
  readonly accepted: () => number;
  readonly port: number;
  readonly close: () => Promise<void>;
}> {
  const sockets = new Set<Socket>();
  let accepted = 0;
  const server = createServer((socket) => {
    accepted += 1;
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("black-hole server has no TCP port");
  return {
    accepted: () => accepted,
    port: address.port,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

describe("dist/main.js over a pipe", () => {
  it("answers a burst in order, one line per request, and nothing else on stdout", async () => {
    const blackHole = await openBlackHole();
    const run = await drive(
      [
        ready(),
        ...Array.from({ length: BURST }, (_, index) => request(index + 1)),
        "",
        "{not json",
      ],
      envFor(blackHole.port),
    ).finally(blackHole.close);

    expect(run.code).toBe(0);

    expect(run.stdout.endsWith("\n")).toBe(true);
    const replyLines = run.stdout.slice(0, -1).split("\n");
    expect(replyLines.every((line) => line.length > 0)).toBe(true);
    const replies = replyLines.map((line) => JSON.parse(line));

    // Ready is answered, the blank line is skipped, and the bad line is answered.
    expect(replies).toHaveLength(BURST + 2);
    // Order, not just presence: replies are matched by position downstream.
    expect(replies.map((reply) => reply.id)).toEqual([
      0,
      ...Array.from({ length: BURST }, (_, i) => i + 1),
      null,
    ]);
    expect(replies[0]).toMatchObject({ ok: true, ready: true, protocolVersion: 1 });
    expect(replies.slice(1, BURST + 1).every((reply) => reply.ok === true)).toBe(true);
    expect(
      replies.slice(1, BURST + 1).every((reply) => /^(?:[0-9a-f]{2})+$/.test(reply.intent)),
    ).toBe(true);
    expect(replies.at(-1)).toMatchObject({ ok: false, code: "bad_request" });
  }, 120_000);

  it("takes startup config from the parent-set environment", async () => {
    const blackHole = await openBlackHole();
    const run = await drive(
      [ready()],
      envFor(blackHole.port),
      CHILD_PROCESS_TIMEOUT_MS,
    ).finally(blackHole.close);

    expect(run.timedOut).toBe(false);
    expect(run.code).toBe(0);
    expect(run.stderr).toContain(`node=ws://127.0.0.1:${blackHole.port}`);
  }, CHILD_PROCESS_TIMEOUT_MS + 5_000);

  it("flushes ready and exits when its publisher warmup never settles", async () => {
    const blackHole = await openBlackHole();
    const httpUrl = `http://127.0.0.1:${blackHole.port}`;
    const wsUrl = `ws://127.0.0.1:${blackHole.port}`;
    try {
      const run = await drive(
        [
          JSON.stringify({
            id: 40,
            op: "ready",
            protocolVersion: 1,
          }),
        ],
        {
          ...STARTUP_ENV,
          MIDNIGHT_PUB_NODE_URL: wsUrl,
          MIDNIGHT_PUB_PROOF_SERVER_URL: httpUrl,
          MIDNIGHT_PUB_INDEXER_URL: `${httpUrl}/api/v3/graphql`,
          MIDNIGHT_PUB_INDEXER_WS_URL: `${wsUrl}/api/v3/graphql/ws`,
        },
        CHILD_PROCESS_TIMEOUT_MS,
      );

      expect(run.timedOut).toBe(false);
      expect(run.code).toBe(0);
      expect(run.stdout.endsWith("\n")).toBe(true);
      expect(
        run.stdout
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line)),
      ).toEqual([
        {
          id: 40,
          ok: true,
          ready: true,
          protocolVersion: 1,
          submitTimeoutMs: 6 * 60 * 1_000,
          recipeTtlMs: 5 * 60 * 1_000,
        },
      ]);
      expect(blackHole.accepted()).toBeGreaterThan(0);
    } finally {
      await blackHole.close();
    }
  }, CHILD_PROCESS_TIMEOUT_MS + 5_000);
});
