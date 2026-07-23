/**
 * midnight-publisher: the localhost-bound Midnight sidecar.
 *
 * Mechanism, never an authority. It holds a funding (gas) wallet and no signing
 * key shares. Every security decision (request-id recompute, proof verification)
 * lives in the `chain-midnight` crate over the raw bytes this service returns,
 * so a decode bug here is a dropped request, never a wrong signature.
 */

import { configFromEnv } from "./config.js";
import { connect } from "./node.js";
import { serve } from "./server.js";

const config = configFromEnv();
const client = await connect(config.nodeUrl);
const server = await serve(config, client);

const shutdown = () => server.close(() => void client.disconnect().finally(() => process.exit(0)));
for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, shutdown);
