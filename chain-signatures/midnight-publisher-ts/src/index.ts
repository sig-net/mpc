// Mechanism, never an authority: this holds a funding wallet and no key shares.
// A decode bug here is a dropped request, never a wrong signature.

import { configFromEnv } from "./config.js";
import { connect } from "./node.js";
import { closePublisher } from "./respond.js";
import { serve } from "./server.js";

// Long enough to unwind, short enough that a stuck wallet cannot keep a hot key resident.
const SHUTDOWN_GRACE_MS = 5_000;

const config = configFromEnv();
const client = await connect(config.nodeUrl);
const server = await serve(config, client, () => stop(1));
for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, () => stop(0));

function stop(code: number): void {
  // An in-flight request keeps `close` from ever calling back, so the timer is
  // what guarantees the process goes away. Sockets are left alone deliberately:
  // destroying them loses the caller the answer the fatal path just flushed.
  setTimeout(() => process.exit(code), SHUTDOWN_GRACE_MS).unref();
  server.close(() => void closePublisher().then(() => client.disconnect()).finally(() => process.exit(code)));
}
