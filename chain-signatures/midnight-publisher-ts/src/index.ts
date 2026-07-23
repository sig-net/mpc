/**
 * midnight-publisher: the localhost-bound Midnight sidecar.
 *
 * Mechanism, never an authority. It holds a funding (gas) wallet and no signing
 * key shares. Every security decision (request-id recompute, proof verification)
 * lives in the `chain-midnight` crate over the raw bytes this service returns,
 * so a decode bug here is a dropped request, never a wrong signature.
 */

import { configFromEnv } from "./config.js";
import { assertArchiveNode } from "./preflight.js";
import { connect } from "./node.js";
import { serve } from "./server.js";

const config = configFromEnv();
const client = await connect(config.nodeUrl);

// State-diff discovery is only sound while state at a block and at its parent
// are both retrievable. Refuse to start on a node that cannot serve them, so a
// pruned endpoint fails loudly here rather than at an arbitrary height weeks on.
await assertArchiveNode(client);

const server = await serve(config, client);

const shutdown = () => server.close(() => void client.disconnect().finally(() => process.exit(0)));
for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, shutdown);
