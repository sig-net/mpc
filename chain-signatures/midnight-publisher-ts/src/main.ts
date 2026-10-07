#!/usr/bin/env node
// stdout carries nothing but reply lines: a stray line desynchronizes the reader for good.

import { createInterface } from "node:readline";

import { configFromEnv } from "./config.js";
import { handleLine } from "./protocol.js";
import { shutdownPublisher } from "./submit.js";

// SDK wallet effects log through the global console; reserve stdout for replies.
console.log = console.error;
console.info = console.error;
console.debug = console.error;

const config = configFromEnv();

console.error(
  `midnight-publisher started network=${config.networkId} node=${new URL(config.endpoints.nodeUrl).origin}`,
);

// Awaited per line, so a slow circuit run's reply cannot be overtaken by the next request's.
for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  if (line.trim().length === 0) continue;
  const reply = await handleLine(config, line);
  await new Promise<void>((resolve, reject) => {
    process.stdout.write(`${reply}\n`, (error) => {
      if (error === undefined || error === null) resolve();
      else reject(error);
    });
  });
}

await shutdownPublisher();
// Every reply write has completed; only SDK handles left by timed-out cleanup can remain.
process.exit(0);
