/**
 * Mechanism, never an authority: this holds a funding wallet and no key shares.
 * Every security decision lives in `chain-midnight` over the bytes it returns,
 * so a decode bug here is a dropped request, never a wrong signature.
 */

import { configFromEnv } from "./config.js";
import { connect } from "./node.js";
import { closePublisher } from "./respond.js";
import { serve } from "./server.js";

const config = configFromEnv();
const client = await connect(config.nodeUrl);
const server = await serve(config, client);

// The wallet facade needs the node connection to unwind, so it stops first.
const shutdown = () =>
  server.close(() => void closePublisher().then(() => client.disconnect()).finally(() => process.exit(0)));
for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, shutdown);
