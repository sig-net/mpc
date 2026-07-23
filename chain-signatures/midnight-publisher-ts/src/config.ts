/** `MIDNIGHT_PUB_*` configuration, keeping the Rust implementation's variable names. */

import { indexerWsUrlFromIndexerUrl, NETWORK_IDS } from "@sig-net/midnight-contract-deploy";

export interface Config {
  readonly port: number;
  /** The loopback boundary IS the access control: no auth, and it holds a funding wallet. */
  readonly bindHost: string;
  /** Substrate ws endpoint. */
  readonly nodeUrl: string;
  /** Mandatory: these contracts are zkir-v3 and cannot be proven locally. */
  readonly proofServerUrl: string;
  /** Where the wallet syncs UTXO and dust state from. */
  readonly indexerUrl: string;
  readonly indexerWsUrl: string;
  /** Root of the compiled-contract assets (`contract/`, `compiler/`, `keys/`, `zkir/`). */
  readonly managedDir: string;
  /** Hot gas-wallet seed. Injected at runtime, never baked into an image. */
  readonly fundingSeed: string;
  readonly networkId: string;
}

/** `FOO=` counts as absent. */
function envOr(key: string, fallback: string): string {
  return process.env[key] || fallback;
}

function envRequired(key: string): string {
  const value = process.env[key];
  if (!value) throw new Error(`${key} must be set`);
  return value;
}

function isLoopback(host: string): boolean {
  return ["localhost", "::1", "[::1]"].includes(host) || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

export function configFromEnv(): Config {
  const bindHost = envOr("MIDNIGHT_PUB_BIND_HOST", "127.0.0.1");
  if (!isLoopback(bindHost) && envOr("MIDNIGHT_PUB_ALLOW_NON_LOOPBACK", "0") !== "1") {
    throw new Error(
      `MIDNIGHT_PUB_BIND_HOST=${bindHost} is not a loopback address. This service has no ` +
        `authentication and holds a funding wallet; set MIDNIGHT_PUB_ALLOW_NON_LOOPBACK=1 only ` +
        `when an authenticated boundary fronts it.`,
    );
  }

  const port = Number.parseInt(envOr("MIDNIGHT_PUB_PORT", "8790"), 10);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`MIDNIGHT_PUB_PORT must be a valid port, got ${envOr("MIDNIGHT_PUB_PORT", "")}`);
  }

  const indexerUrl = envRequired("MIDNIGHT_PUB_INDEXER_URL");

  // Unvalidated, a typo here builds a wallet at a DIFFERENT unshielded address,
  // proves a call, spends dust, and fails only at the node as `InvalidNetworkId`
  // — or earlier as the same misleading "could not balance dust". The library
  // owns the closed set; nothing here restates it.
  const networkId = envOr("MIDNIGHT_PUB_NETWORK_ID", "undeployed");
  if (!(NETWORK_IDS as readonly string[]).includes(networkId)) {
    throw new Error(`MIDNIGHT_PUB_NETWORK_ID=${networkId} is not one of ${NETWORK_IDS.join(", ")}`);
  }

  return {
    port,
    bindHost,
    nodeUrl: envRequired("MIDNIGHT_PUB_NODE_URL"),
    proofServerUrl: envRequired("MIDNIGHT_PUB_PROOF_SERVER_URL"),
    indexerUrl,
    // A segment deeper than the query endpoint. Getting it wrong is silent: the
    // facade never syncs and it surfaces as "could not balance dust".
    indexerWsUrl: envOr("MIDNIGHT_PUB_INDEXER_WS_URL", indexerWsUrlFromIndexerUrl(indexerUrl)),
    managedDir: envRequired("MIDNIGHT_PUB_MANAGED_DIR"),
    // Never defaulted: a fallback is a real hot wallet seed shipped in the image.
    fundingSeed: envRequired("MIDNIGHT_PUB_FUNDING_SEED"),
    networkId,
  };
}

/** Dependency errors echo values they were handed, and that text becomes a response body. */
export function redact(text: string, values: readonly string[]): string {
  // Load-bearing: `split("")` would explode the text into characters and rejoin
  // it with a placeholder between every one.
  return values.reduce((out, value) => (value ? out.split(value).join("<redacted>") : out), text);
}
