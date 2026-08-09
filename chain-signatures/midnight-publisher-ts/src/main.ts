#!/usr/bin/env node
// The entry point: stdin is the request stream, stdout is the reply stream, and
// nothing but replies is ever written to it. Every diagnostic goes to stderr,
// because a stray line on stdout desynchronizes the reader for good.

import { createInterface } from "node:readline";

import { configFromEnv } from "./config.js";
import { handleLine } from "./protocol.js";
import { closePublisher } from "./submit.js";

const config = configFromEnv();

console.error(
  `midnight-publisher: managed dir ${config.managedDir}, network ${config.networkId}, ` +
    `${config.endpoints === undefined ? "no funding wallet (builds intents only)" : `node ${config.endpoints.nodeUrl}`}`,
);

// Awaited per line, so a circuit run that takes seconds cannot have its reply
// overtaken by the next request's.
for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  if (line.trim().length === 0) continue;
  process.stdout.write(`${await handleLine(config, line)}\n`);
}

// A synced wallet holds an indexer subscription and a node socket, both of which keep
// the loop alive after stdin closes. Still no explicit exit: letting the process end on
// its own flushes the last reply that an `exit` would truncate.
await closePublisher();
