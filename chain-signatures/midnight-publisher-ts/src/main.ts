#!/usr/bin/env node
// stdout carries nothing but reply lines: a stray line desynchronizes the reader for good.

import { createInterface } from "node:readline";

import { configFromEnv } from "./config.js";
import { handleLine } from "./protocol.js";
import { closePublisher } from "./submit.js";

const config = configFromEnv();

console.error(
  `midnight-publisher started managed_dir=${config.managedDir} network=${config.networkId} ` +
    `node=${config.endpoints === undefined ? "none (builds intents only)" : config.endpoints.nodeUrl}`,
);

// Awaited per line, so a slow circuit run's reply cannot be overtaken by the next request's.
for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  if (line.trim().length === 0) continue;
  process.stdout.write(`${await handleLine(config, line)}\n`);
}

// No explicit exit: ending naturally flushes the last reply that an exit would truncate.
await closePublisher();
