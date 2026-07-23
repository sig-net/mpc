/**
 * Environment configuration, deliberately identical in shape and variable names
 * to the Rust implementation this replaces, so a deployment moves without an
 * env change. Two rules are load-bearing and are enforced here rather than by
 * convention: the service binds loopback only, and every secret is required
 * rather than defaulted.
 */

/** Intent-generation modes the Rust implementation carried. Only `native` survives: the toolkit CLI is gone. */
export interface Config {
  readonly port: number;
  /**
   * Interface to bind to. The loopback boundary IS this service's access
   * control: it has no authentication of any kind and it holds a funding
   * wallet. Binding it somewhere reachable must be a deliberate, spelled-out
   * act behind an external authenticated boundary, never a typo in an env var.
   */
  readonly bindHost: string;
  /** Substrate ws endpoint of the Midnight node. */
  readonly nodeUrl: string;
  /** Proof-server base URL. Mandatory: these contracts are zkir-v3 and cannot be proven locally. */
  readonly proofServerUrl: string;
  /** Indexer endpoint the wallet syncs UTXO and dust state from. See doc/midnight-publisher-language-decision.md §2.5. */
  readonly indexerUrl: string;
  readonly indexerWsUrl: string;
  /** Root of the compiled-contract assets (`contract/`, `compiler/`, `keys/`, `zkir/`). */
  readonly managedDir: string;
  /** Hot gas-wallet seed. Injected at runtime, NEVER baked into an image. */
  readonly fundingSeed: string;
  /** Midnight network id (`undeployed` locally). */
  readonly networkId: string;
}

/** An empty variable counts as absent: `FOO=` is a mistake, never a deliberate empty value. */
function envOr(key: string, fallback: string): string {
  return process.env[key] || fallback;
}

function envRequired(key: string): string {
  const value = process.env[key];
  if (!value) throw new Error(`${key} must be set`);
  return value;
}

/**
 * Derive the indexer's WebSocket URL from its HTTP URL.
 *
 * The subscription endpoint is NOT the query endpoint with a swapped scheme:
 * it lives one path segment deeper, at `/ws`. Verified against the running
 * indexer, which answers a WebSocket upgrade on `/api/v3/graphql` with 405
 * Method Not Allowed and only accepts the handshake on `/api/v3/graphql/ws`,
 * and against `@sig-net/midnight-contract-deploy`'s `DEFAULT_ENDPOINTS`, where
 * every network carries the `/ws` suffix.
 *
 * Getting this wrong is silent: the wallet facade never syncs, and the failure
 * surfaces as `Wallet.InsufficientFunds: could not balance dust` rather than as
 * a connection error.
 *
 * @param indexerUrl - The indexer's HTTP(S) query URL.
 * @returns The ws(s) subscription URL.
 */
export function indexerWsUrlFrom(indexerUrl: string): string {
  const url = new URL(indexerUrl);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = `${url.pathname.replace(/\/$/, "")}/ws`;
  return url.toString();
}

function isLoopback(host: string): boolean {
  const named = ["localhost", "::1", "[::1]"].includes(host);
  return named || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

/**
 * Build the config from `MIDNIGHT_PUB_*` environment variables.
 *
 * @returns The validated configuration.
 * @throws If a required variable is absent, or if a non-loopback bind is
 *   requested without the explicit `MIDNIGHT_PUB_ALLOW_NON_LOOPBACK=1` opt-in.
 */
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

  return {
    port,
    bindHost,
    nodeUrl: envRequired("MIDNIGHT_PUB_NODE_URL"),
    proofServerUrl: envRequired("MIDNIGHT_PUB_PROOF_SERVER_URL"),
    indexerUrl,
    indexerWsUrl: envOr("MIDNIGHT_PUB_INDEXER_WS_URL", indexerWsUrlFrom(indexerUrl)),
    managedDir: envRequired("MIDNIGHT_PUB_MANAGED_DIR"),
    // Required, never defaulted: a baked-in fallback is a real hot wallet seed
    // that ships in the binary and silently works in production.
    fundingSeed: envRequired("MIDNIGHT_PUB_FUNDING_SEED"),
    networkId: envOr("MIDNIGHT_PUB_NETWORK_ID", "undeployed"),
  };
}

/** The values that must never reach a log line or an HTTP response body. */
export function secrets(config: Config): readonly string[] {
  return [config.fundingSeed].filter((s) => s.length > 0);
}

/**
 * Replace every occurrence of a secret with a placeholder.
 *
 * Error text from the wallet, the proof server, or the node can echo values it
 * was handed. That text becomes a 502 body and a log line, so it is redacted at
 * the source and every later consumer is safe by construction.
 *
 * @param text - The text to redact.
 * @param values - The secret values to remove.
 * @returns The text with every secret replaced by `<redacted>`.
 */
export function redact(text: string, values: readonly string[]): string {
  // The empty-string guard is load-bearing: `split("")` would explode the text
  // into characters and rejoin it with a placeholder between every one.
  return values.reduce((out, value) => (value ? out.split(value).join("<redacted>") : out), text);
}
