/**
 * `MIDNIGHT_PUB_*` environment configuration, keeping the Rust implementation's
 * variable names so a deployment moves without an env change.
 */

export interface Config {
  readonly port: number;
  /**
   * The loopback boundary IS this service's access control: no authentication of
   * any kind, and it holds a funding wallet.
   */
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

/** An empty variable counts as absent: `FOO=` is a mistake, not a deliberate empty value. */
function envOr(key: string, fallback: string): string {
  return process.env[key] || fallback;
}

function envRequired(key: string): string {
  const value = process.env[key];
  if (!value) throw new Error(`${key} must be set`);
  return value;
}

/**
 * The subscription endpoint is not the query endpoint with a swapped scheme: it
 * lives one segment deeper, at `/ws`. The running indexer answers an upgrade on
 * `/api/v3/graphql` with 405 and only shakes hands on `/api/v3/graphql/ws`.
 *
 * Getting this wrong is silent. The facade never syncs and it surfaces as
 * `Wallet.InsufficientFunds: could not balance dust`, not as a connection error.
 */
export function indexerWsUrlFrom(indexerUrl: string): string {
  const url = new URL(indexerUrl);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = `${url.pathname.replace(/\/$/, "")}/ws`;
  return url.toString();
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

  return {
    port,
    bindHost,
    nodeUrl: envRequired("MIDNIGHT_PUB_NODE_URL"),
    proofServerUrl: envRequired("MIDNIGHT_PUB_PROOF_SERVER_URL"),
    indexerUrl,
    indexerWsUrl: envOr("MIDNIGHT_PUB_INDEXER_WS_URL", indexerWsUrlFrom(indexerUrl)),
    managedDir: envRequired("MIDNIGHT_PUB_MANAGED_DIR"),
    // Never defaulted: a fallback here is a real hot wallet seed shipped in the
    // image that silently works in production.
    fundingSeed: envRequired("MIDNIGHT_PUB_FUNDING_SEED"),
    networkId: envOr("MIDNIGHT_PUB_NETWORK_ID", "undeployed"),
  };
}

/** Values that must never reach a log line or a response body. */
export function secrets(config: Config): readonly string[] {
  return [config.fundingSeed].filter((s) => s.length > 0);
}

/**
 * Wallet, proof-server and node errors can echo values they were handed, and
 * that text becomes both a response body and a log line, so it is redacted at
 * the source.
 */
export function redact(text: string, values: readonly string[]): string {
  // Belt and braces: `envRequired` and `secrets()` both already exclude an
  // empty seed, but `redact` is exported and takes an arbitrary array, and
  // `split("")` would explode the text into characters and rejoin it with a
  // placeholder between every one.
  return values.reduce((out, value) => (value ? out.split(value).join("<redacted>") : out), text);
}
