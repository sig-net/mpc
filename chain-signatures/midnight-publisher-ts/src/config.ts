// `MIDNIGHT_PUB_*` configuration. The variable names are the deployment contract; never rename casually.
//
// Two halves, because the process answers two operations. Building an intent needs the
// compiled assets and the network id and nothing else. Submitting one needs a funding
// wallet, and a funding wallet needs every endpoint plus the seed.
//
// The submit half is optional AS A SET: a deployment that only reads the chain never
// submits and still has to start, while one that does submit must not discover a
// missing endpoint on its first real signature. All five or none; anything between
// fails here, naming what is missing.
//
// `MIDNIGHT_PUB_PORT`, `MIDNIGHT_PUB_BIND_HOST` and `MIDNIGHT_PUB_ALLOW_NON_LOOPBACK`
// do not come back with the wallet. They guarded an unauthenticated HTTP listener
// against the network, and there is no listener: the only thing that can reach this
// process is the parent that spawned it, down its own pipe.

import { z } from "zod";

import { NETWORK_IDS } from "@sig-net/midnight-contract-deploy";

/** Where the funding wallet reaches the chain. Present or absent as a whole. */
export interface Endpoints {
  readonly nodeUrl: string;
  // Mandatory: these contracts are zkir-v3 and cannot be proven locally.
  readonly proofServerUrl: string;
  // The wallet's spendable DUST is derived by replaying every block's ledger events
  // from genesis, and the indexer is the only surface that serves them. No node RPC
  // carries it, which is why the wallet cannot move to the caller.
  readonly indexerUrl: string;
  readonly indexerWsUrl: string;
}

export interface Config {
  // Root of the compiled-contract assets (`contract/`, `compiler/`, `keys/`, `zkir/`).
  readonly managedDir: string;
  readonly networkId: string;
  /** Absent on a deployment that only builds intents. Present implies the seed is set too. */
  readonly endpoints: Endpoints | undefined;
}

const FUNDING_SEED_VAR = "MIDNIGHT_PUB_FUNDING_SEED";

// A hex seed is at least 16 bytes, so nothing shorter than this is one and nothing
// shorter may be blanked out of a message: a two-character "secret" would redact
// half the text it appears in.
const SHORTEST_SEED_HEX = 32;

// The two the builder alone needs. Required: the operator supplies them, nothing is defaulted.
const EnvSchema = z.object({
  MIDNIGHT_PUB_MANAGED_DIR: z.string().min(1),
  // A typo here builds a wallet at a DIFFERENT unshielded address, proves a call, and
  // spends dust, failing only later at the node. The library owns the closed set.
  MIDNIGHT_PUB_NETWORK_ID: z.literal(NETWORK_IDS, `must be one of ${NETWORK_IDS.join(", ")}`),
  // Optional individually and checked as a set below: zod can express "all or none"
  // only as a union, whose message names the shape instead of the missing variable.
  MIDNIGHT_PUB_NODE_URL: z.string().optional(),
  MIDNIGHT_PUB_PROOF_SERVER_URL: z.string().optional(),
  MIDNIGHT_PUB_INDEXER_URL: z.string().optional(),
  MIDNIGHT_PUB_INDEXER_WS_URL: z.string().optional(),
  [FUNDING_SEED_VAR]: z.string().optional(),
});

// Paired with the field each fills, so the refusal names the variable an operator sets
// while the code reads the field.
const SUBMIT_VARS = [
  ["MIDNIGHT_PUB_NODE_URL", "nodeUrl"],
  ["MIDNIGHT_PUB_PROOF_SERVER_URL", "proofServerUrl"],
  ["MIDNIGHT_PUB_INDEXER_URL", "indexerUrl"],
  ["MIDNIGHT_PUB_INDEXER_WS_URL", "indexerWsUrl"],
  [FUNDING_SEED_VAR, "fundingSeed"],
] as const;

/** The set a submit needs, for the refusal a build-only deployment answers with. */
export const SUBMIT_VAR_NAMES: readonly string[] = SUBMIT_VARS.map(([name]) => name);

function endpointsFromEnv(env: z.infer<typeof EnvSchema>): Endpoints | undefined {
  // Empty counts as absent: the parent sets `MIDNIGHT_PUB_FUNDING_SEED` unconditionally
  // and blanks it on a deployment that never spends.
  const supplied = {
    nodeUrl: env.MIDNIGHT_PUB_NODE_URL ?? "",
    proofServerUrl: env.MIDNIGHT_PUB_PROOF_SERVER_URL ?? "",
    indexerUrl: env.MIDNIGHT_PUB_INDEXER_URL ?? "",
    indexerWsUrl: env.MIDNIGHT_PUB_INDEXER_WS_URL ?? "",
    // Read here only to classify the deployment. It is deliberately not carried into
    // the returned `Config`, so nothing that renders a config can render the seed.
    fundingSeed: env[FUNDING_SEED_VAR] ?? "",
  };

  const missing = SUBMIT_VARS.filter(([, field]) => supplied[field].length === 0).map(([name]) => name);
  if (missing.length === SUBMIT_VARS.length) return undefined;
  if (missing.length > 0) {
    throw new Error(
      `invalid MIDNIGHT_PUB_* configuration: submitting needs all of ${SUBMIT_VAR_NAMES.join(", ")}, ` +
        `or none of them for a deployment that only builds intents; missing ${missing.join(", ")}`,
    );
  }

  return {
    nodeUrl: supplied.nodeUrl,
    proofServerUrl: supplied.proofServerUrl,
    indexerUrl: supplied.indexerUrl,
    indexerWsUrl: supplied.indexerWsUrl,
  };
}

export function configFromEnv(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    const detail = parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");
    throw new Error(`invalid MIDNIGHT_PUB_* configuration: ${detail}`);
  }

  return {
    managedDir: parsed.data.MIDNIGHT_PUB_MANAGED_DIR,
    networkId: parsed.data.MIDNIGHT_PUB_NETWORK_ID,
    endpoints: endpointsFromEnv(parsed.data),
  };
}

// Read at the point of use rather than carried on `Config`: the seed is the one secret
// this process holds, and a value that is never in a struct cannot be logged with one.
export function fundingSeed(): string {
  const seed = process.env[FUNDING_SEED_VAR];
  if (seed === undefined || seed.length === 0) throw new Error(`${FUNDING_SEED_VAR} is required`);
  return seed;
}

/**
 * `text` with the funding seed blanked, in every spelling the seed parser accepts.
 *
 * Applied to everything on its way to stdout or the log. Every failure past the wallet
 * boundary belongs to a dependency, and one that quotes its own input would otherwise
 * put the seed in a reply line and from there into the parent node's log.
 */
export function redactSeed(text: string): string {
  const raw = process.env[FUNDING_SEED_VAR]?.trim();
  if (raw === undefined || raw.length < SHORTEST_SEED_HEX) return text;

  const spellings = new Set([raw, raw.replace(/^0x/i, "").toLowerCase(), raw.replace(/^0x/i, "").toUpperCase()]);
  let redacted = text;
  for (const spelling of spellings) redacted = redacted.split(spelling).join("[redacted]");
  return redacted;
}
