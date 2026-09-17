# Log Level Policy

**error** means a human needs to look at it: the node will not recover on its own, or correctness may
be affected. **warn** means the node is degraded but expected to self-heal through its normal
mechanisms (retry, reorganization, resync), escalating to error if it doesn't. Everything else —
routine operation, expected transitions, diagnostics — is **info** or **debug**. The test for any warn
or error: if on-call would gain nothing from reading it, it does not belong at that level. 

## Choosing a level

1. Expected as part of normal operation → info or debug.
2. Per-attempt output of retries or polling → rate-limit: one entry per interval with a count, not
   one entry per occurrence.
3. Fault requiring intervention → error.

## Guidelines

- One event, one entry: flatten anyhow `Caused by:` chains rather than emitting multi-line output.
- Log metadata, not payloads: no binaries, contract bytecode, or other bulky data — reference them by
  hash or id instead.
