# Dependencies

How the repository adds, declares, checks and updates what it takes from
outside: Rust crates, the toolchain and tools, GitHub Actions and container
images. The crate rules cover dev- and build-dependencies too.

## Principles

1. **Fewer dependencies.** A crate runs in the node next to the key shares,
   and its build script and proc macros run in CI with CI's credentials.
2. **Pinned inputs.** A build takes the same versions on every machine and
   every day, never `latest`.
3. **Enforced by CI.** Every rule a tool can check fails CI when broken, so
   reviewers do not have to catch it.
4. **Small, regular updates.** A security fix is never a jump over major
   versions.

## Adding a dependency

- **A1. Needed.** The standard library, a dependency we already have, or a
  few lines of our own code cannot do the job. The PR states the use case.
- **A2. Maintained.** It has recent releases and its security reports get
  answered.
- **A3. Allowed source and license.** `deny.toml` allows crates from
  crates.io and from two `sig-net` git repositories (`[sources]`), under
  permissive licenses such as MIT and Apache-2.0 (`[licenses]`). Widening
  either list is a PR of its own.
- **A4. No second version of a crate we already build.** If `Cargo.lock` has
  `sha2 0.11`, prefer a release of the new crate that also uses `0.11`.
  `cargo tree -i sha2` shows which crate uses which version.
- **A5. Only the features it needs.** The rest are off
  (`default-features = false`).

## Manifests

- **M1. Declared once.** A crate used in more than one place is declared in
  `[workspace.dependencies]` of the root `Cargo.toml`. A member writes
  `workspace = true` and adds only the features it needs. A member that needs
  another major version declares it itself, with a comment: `chain-midnight`
  keeps `sha2 0.10` because `hmac 0.12` requires it.
- **M2. A plain version.** `"0.13.1"`, never `*`.
- **M3. An exact pin has a reason.** `"=1.0.38"` blocks every update of the
  crate, security fixes included, so a comment says why it is pinned.
- **M4. A git dependency names the full commit hash** in `rev`, never a
  branch or a tag.
- **M5. Nothing unused.** `cargo machete --fix` removes an unused dependency.
  The `ignored` list under `[package.metadata.cargo-machete]` is only for a
  crate machete cannot see, such as `serde_bytes`, which the code names only
  inside `#[serde(with = "serde_bytes")]`.
- **M6. `Cargo.lock` is committed** and fixes the version we build. A PR
  changes it only as far as its own manifest change requires; other version
  changes go through [Updating](#updating).

```toml
# Cargo.toml
[workspace.dependencies]
sha2 = "0.11.0"                                      # M1, M2
cait-sith = { git = "…", rev = "<40-char hash>" }    # M4

# chain-signatures/tron-wire/Cargo.toml
[dependencies]
sha2.workspace = true                                # M1
```

## Toolchain, tools, actions and images

- **T1. One Rust version.** The exact release in `rust-toolchain.toml`. The
  workflows and the `Dockerfile` repeat it and change in the same PR.
- **T2. Exact versions.** A tool that a workflow downloads and an image tag
  name an exact version, and `scripts/setup-deps.sh` installs the same ones.
  The exception is `debian:bookworm-slim`, the base of the release image: it
  floats because its `apt-get install` takes Debian's current packages
  anyway.
- **T3. Actions by commit.** An action is referenced by its full commit SHA,
  with the version in a comment (`actions/checkout@<sha> # v6`). A tag can be
  moved to other code, a commit cannot.
- **T4. Downloads are verified.** A file the `Dockerfile` downloads, such as
  the Midnight prover keys and ZK parameters, is checked with `sha256sum`
  against a hash written in the `Dockerfile`.

## Checks

The `Dependency Audit` job runs on every PR and merge-queue run. `just audit`
runs the same locally.

- **C1. [`cargo deny check`](https://embarkstudios.github.io/cargo-deny/)**,
  configured in `deny.toml`: known vulnerabilities from
  [RustSec](https://rustsec.org/), sources and licenses (A3), duplicate and
  `*` declarations (M1, M2). `unmaintained` and `unsound` advisories only
  warn.
- **C2. [`cargo machete`](https://github.com/bnjbvr/cargo-machete)**: unused
  dependencies (M5).
- **C3. `Cargo.lock` in sync** (M6). The `Lint & Unit Tests` job fails when
  its build changes the lockfile.

## Updating

An update is a `chore(deps)` PR with nothing else in it.

- **U1. Security first.** A new advisory fails C1 on every open PR, so its
  fix goes before them: an update, or an entry on the `ignore` list in
  `deny.toml` when no fixed version can be taken or our code cannot reach
  the vulnerable part. The entry's `reason` says which, and what has to
  change to drop it; the PR that removes the blocker removes the entry.
- **U2. Routine, after each release.** Right after a release is cut, one PR
  runs `cargo update`.
- **U3. One major version per PR**, or one family that moves together, like
  the `near-*` crates.
- **U4. The rest when needed.** The toolchain, tools, actions and images are
  updated when a fix or a feature needs it.
