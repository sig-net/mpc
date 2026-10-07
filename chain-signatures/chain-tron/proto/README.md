# Vendored protobuf schemas

Copied verbatim from [tronprotocol/protocol](https://github.com/tronprotocol/protocol). These files are the wire truth for the
crate: field names, casings, tags, and enum values (e.g.
`Return.response_code`, `AccountResourceMessage`) come from here, not from
hand-rolled structs or memory.

`build.rs` compiles them with `protox` + `prost-build` into Rust types that
`src/pb.rs` re-exports. Nothing reads the `.proto` files at runtime.

## Why two representations?

The same java-tron message reaches us in two encodings, and the crate keeps
separate types for each:

- **Protobuf binary** (tx assembly and signing):
  generated `pb::*` types only; no hand-rolled structs on this path.
- **HTTP JSON** (receipts, blocks, resources): prost types cannot parse it —
  it is not proto3-JSON (bytes as hex, the `SUCESS` enum typo, providers
  omitting fields like `contractRet`). Private wire structs + lean domain
types (`types.rs`) handle this path.

The two must agree on field names and casings: the vendored proto is the
reference, and the recorded fixtures in `tests/fixtures/` enforce it.

To update: re-copy the files from upstream (with their dependency closure),
then `cargo test` — the recorded mainnet fixtures in `tests/fixtures/` fail
if wire shapes drift.
