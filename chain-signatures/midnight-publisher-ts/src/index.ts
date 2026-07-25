/**
 * Mechanism, never an authority: this holds a funding wallet and no key shares.
 * Every security decision lives in `chain-midnight` over the bytes it returns,
 * so a decode bug here is a dropped request, never a wrong signature.
 */

import { configFromEnv } from "./config.js";
import { connect } from "./node.js";
import { closePublisher } from "./respond.js";
import { serve } from "./server.js";

/** Long enough for the wallet to unwind, short enough that a stuck one cannot keep a hot key resident. */
const SHUTDOWN_GRACE_MS = 5_000;

const config = configFromEnv();
const client = await connect(config.nodeUrl);
const server = await serve(config, client, () => stop(1));
for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, () => stop(0));

/** The wallet facade needs the node connection to unwind, so it stops first. */
function stop(code: number): void {
  // An in-flight request keeps `close` from ever calling back, and a wallet that
  // will not close keeps this from ever exiting, so the timer is what actually
  // guarantees the process goes away. Sockets are left alone deliberately: the
  // fatal path calls this the instant a reply is flushed, and destroying that
  // connection is how a caller loses the answer it is being stopped to receive.
  setTimeout(() => process.exit(code), SHUTDOWN_GRACE_MS).unref();
  server.close(() => void closePublisher().then(() => client.disconnect()).finally(() => process.exit(code)));
}
