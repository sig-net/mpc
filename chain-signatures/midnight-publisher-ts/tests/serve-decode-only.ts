/**
 * The REAL server, chain-free: `serve()` with a node client that throws on any
 * access. Everything `src/index.ts` boots is here except the node connection,
 * which `POST /respond` alone needs, so the decode seams and `GET /health` are
 * served exactly as in production and nothing dials a chain.
 *
 * It exists so a consumer in another language can drive the shipped routes over
 * real HTTP without the stack. `chain-midnight`'s `tests/sidecar_live.rs` spawns
 * it; that file carries the runbook. By hand:
 *
 *   npm ci
 *   MIDNIGHT_PUB_PORT=8790 \
 *   MIDNIGHT_PUB_BIND_HOST=127.0.0.1 \
 *   MIDNIGHT_PUB_NODE_URL=ws://127.0.0.1:1 \
 *   MIDNIGHT_PUB_PROOF_SERVER_URL=http://127.0.0.1:1 \
 *   MIDNIGHT_PUB_INDEXER_URL=http://127.0.0.1:1 \
 *   MIDNIGHT_PUB_INDEXER_WS_URL=ws://127.0.0.1:1 \
 *   MIDNIGHT_PUB_MANAGED_DIR=$PWD/tests/fixtures \
 *   MIDNIGHT_PUB_FUNDING_SEED=0000000000000000000000000000000000000000000000000000000000000001 \
 *   MIDNIGHT_PUB_NETWORK_ID=undeployed \
 *   node --import tsx tests/serve-decode-only.ts
 *
 * Not a `*.test.ts`, so `vitest run` never picks it up, and not a second entry
 * point either: `src/index.ts` stays the only thing deployed. `POST /respond` is
 * still routed and will fail (it needs the wallet and the node), which is why
 * every endpoint above is a dead port. The forbidden client is this side's own
 * claim under test: it proves the decode seams open no connection, rather than
 * merely not needing one.
 */

import { configFromEnv } from "../src/config.js";
import { serve } from "../src/server.js";
import { forbiddenClient } from "./support.js";

await serve(configFromEnv(), forbiddenClient("a decode seam touched the node client"));
