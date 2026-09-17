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
  entry per occurrence.
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
