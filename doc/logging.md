# Log Level Policy

**error** means a human needs to look at it: the node will not recover on its own, or correctness may
be affected. **warn** means the node is degraded but expected to self-heal through its normal
mechanisms (retry, reorganization, resync), escalating to error if it doesn't. Everything else —
routine operation, expected transitions, diagnostics — is **info** or **debug**. The test for any warn
or error: if on-call would gain nothing from reading it, it does not belong at that level.

## Guidelines

- Keep the message a static string; put data in fields, so entries group by message and can be
  queried by field.
- One event, one entry: flatten anyhow `Caused by:` chains rather than emitting multi-line output.
- Rate-limit per-attempt output of retries or polling: one entry per interval with a count, not one
  entry per occurrence. For events that repeat per state-machine round (e.g. reorganization), sample
  by progression — warn on the first round, then at most once per N rounds advanced — instead of
  logging each round.
- Log metadata, not payloads: no binaries, contract bytecode, or other bulky data — reference them by
  hash or id instead.
- Never log secrets, including URLs carrying API keys — log the host only. See
  `doc/SECRET_MANAGEMENT.md`.

## Examples

```rust
// good: static message, data in fields
tracing::info!(%chain, height, "processed block");
tracing::warn!(%chain, error = %format_args!("{err:#}"), "chain run() failed; restarting");

// bad: data baked into the message — breaks grouping and field queries
tracing::info!("Processing block number {} with hash {:?}", number, hash);

// bad: Debug of an anyhow error — the multi-line `Caused by:` chain splits into orphan entries
tracing::warn!(?result, %chain, "chain run() failed; restarting");

// good: rate-limited, carries the occurrence count
if let Some(count) = mpc_utils::throttle::check("posit:presig-return-rejects") {
    tracing::warn!(count, ?sign_id, "returning presignature to pool due to REJECTs");
}

// bad: one entry per occurrence
tracing::warn!(?sign_id, "returning presignature to pool due to REJECTs");
```

## Outputs

Logging is built from independent layers in `node/src/logs.rs`; each has its own destination and
filter:

| Output | Destination | Enabled by | Filter |
|---|---|---|---|
| FMT | console (stderr), human-readable | always | `RUST_LOG` |
| OTLP | OpenTelemetry collector → tracing backends | always; endpoint `MPC_OTLP_ENDPOINT` / `--otlp-endpoint` (default `http://localhost:4318`) | none — call-site levels only |
| Stackdriver | GCP Cloud Logging, structured stderr | on GCP unless `MPC_DISABLE_GCP_LOGS` / `--disable-gcp-logs` | `RUST_LOG` |

`--opentelemetry-level` (`MPC_OPENTELEMETRY_LEVEL`) is accepted but not yet wired to the OTLP
layer; it currently has no effect.

### Local OTLP setup

1. Start a local collector, e.g. [Jaeger all-in-one](https://www.jaegertracing.io/docs/getting-started/).
2. Run the node — it exports to `http://localhost:4318` by default; override with `MPC_OTLP_ENDPOINT`
   or `--otlp-endpoint`.
3. Open the backend UI to explore logs and traces.
