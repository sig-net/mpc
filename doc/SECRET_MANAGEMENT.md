# In-Memory Secret Management Policy

How secret material is represented, passed around, logged, and stored across
the workspace and the integration-test harness.

## What counts as a secret

- The node's root keyshare and any protocol intermediates (triple/presignature
  shares, decrypted inter-node messages).
- Any chain account key used to sign transactions.
- Mesh keys: the inter-node signing key and cipher key.
- Infrastructure credentials (cloud service accounts, connection URLs with
  passwords).
- Any encoding of the above (hex, base58, serialized structs).

## Core principle

A secret must be protected by its **type**, not by every containing struct
remembering to redact it. Leaking a secret must require a visible, greppable
act (`expose_secret()`), never an accidental `#[derive(Debug)]` or `{:?}`.

## Rules

1. **Wrap at entry.** A secret entering the process (CLI/env/file) goes into a
   [`secrecy`](https://docs.rs/secrecy) wrapper (`SecretString`,
   `SecretBox<T>`) immediately. Never carry a secret as a bare `String` or
   `Vec<u8>` across a function boundary.
2. **Redacting types.** Our own key types must have a fully redacting `Debug`
   and no `Display`. Third-party key types whose `Debug`/`Display` print key
   material (e.g. `near_crypto::SecretKey`) must not appear in structs that
   derive `Debug`, `Display`, or `Serialize` — wrap them in `SecretBox`.
   A redacted field always prints the literal `"<hidden>"` — one consistent
   marker everywhere. Manual `Debug` impls on secret-bearing structs end with
   `finish_non_exhaustive()` so later-added fields are omitted by default.
3. **Point-of-use exposure.** Unwrap (`expose_secret()`, `to_bytes()`) only to
   sign, decrypt, parse, or write to secret storage. Never store the exposed
   copy in a field, channel, or long-lived `String`; minimize clones and
   intermediate encodings.
4. **Zero key material in logs.** No secrets in logs, errors, panics, metrics,
   or traces — in any encoding, at any truncation. A prefix of a key is a
   leak, not a redaction. To correlate keys in logs, use the public
   counterpart or a fingerprint.
5. **Serialization only for secret storage.** `Serialize` on a secret-bearing
   type exists solely for its dedicated storage path (`SecretNodeStorage`).
   Secrets never go to Redis, general configs, or any other store.
6. **At rest.** Production: cloud secret manager only — secrets are never
   written to plain files. No secrets in git — test keys are generated at
   runtime, never hard-coded.
7. **Process boundaries.** Secrets enter via env vars or files, never argv, in
   production — argv is world-readable. The test harness's argv spawning is
   local-only and never used with real keys.

## Planned enforcement automation

Each rule gets a mechanical check; discipline is the fallback, not the plan.

### Compile-time

- **Clippy config**: `clippy.toml` `disallowed-types` for printable third-party
  key types (e.g. `near_crypto::SecretKey`), so every legitimate use site
  carries a visible `#[allow]`; workspace lints deny `dbg_macro` and
  `print_stdout` (rules 1–4).
- **Static trait assertions**: our secret types must implement neither
  `Display` nor `Serialize` — asserted at compile time
  (`assert_not_impl_any!`) so the impl can never be added back (rules 2, 5).

### Test-time

- **Redaction unit tests**: for every secret-bearing type, construct it with a
  known key and assert `{:?}` prints `"<hidden>"` and never the key material —
  in raw, hex, or base58 form (rules 2, 4).
- **Integration log tripwire**: the test harness knows every key it generates;
  scan spawned-node output for any of them in any encoding and fail the run on
  a hit. Catches leaks through dependencies that no type-level control sees
  (rule 4).

### Repository scanning

- **gitleaks in CI** (and GitHub push protection when available): block secrets
  from entering git history; allowlist only documented throwaway test vectors
  (rule 6).

### Review routing

- **CODEOWNERS** on secret-bearing paths (`keys/`, chain configs, this file):
  every diff touching secret handling gets a designated reviewer.
