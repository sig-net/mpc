# component-tests

A small workspace crate for short-running, component-style tests that rely on the
integration-tests harness (MpcEnv / MpcFixture) but do not require a full
prebuild of contracts or the `mpc-node` binary.

Run component-focused tests like this (skips prebuild automatically):

```bash
cargo test -p component-tests -- --nocapture
```

These tests will be executed with `CARGO_PKG_NAME=component-tests`, and our
`setup.sh` will automatically avoid running heavy prebuilds for `component-tests`.
