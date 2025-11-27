## ed25519-dalek backport / mitigation plan

Goal: close RUSTSEC-2022-0093 (Double Public Key Signing Function Oracle Attack) by either
1) upgrading to `ed25519-dalek >= 2.0` (preferred), or
2) backporting the necessary API restrictions from 2.x into a 1.x fork and patching dependent consumers.

Notes:
- The RustSec advisory references that v2 introduces safer APIs and removes the decoupled private/public signing API.
- Solana currently pins 1.x; this blocks a direct upgrade. We therefore have two realistic options:
  - Wait for Solana to upgrade to ed25519-dalek >= 2.x, then remove the advisory.
  - Maintain a fork of ed25519-dalek that backports the API changes required to avoid the vulnerability (for example, remove or restrict Keypair::from_bytes or make signing require a SigningKey type). This requires careful testing.

Suggested backport steps (high-level):
1. Fork https://github.com/dalek-cryptography/ed25519-dalek.
2. Create branch `v1-backport-security` from `refs/tags/1.0.1` (the one Solana uses).
3. Cherry-pick or implement the changes from 2.x that eliminate decoupled keypair signing; at minimum, audit and remove direct signing APIs which accept raw public key and private bytes separately. See v2 changes adding `hazmat` module.
4. Add tests verifying that signing with a decoupled public key can't be used to derive the private key; also assert a safer, recommended high-level API is used.
5. Publish test releases as `0.1.1-v1-backport` in your fork or keep it only in the `git` hosted fork for now.
6. In our repository: add a `[patch.crates-io]` entry into `Cargo.toml` referencing your fork/branch/commit to inject the patched version.
7. Run `cargo update -p ed25519-dalek` and run the full unit + integration test suite; if the backport breaks Solana behavior (likely if you alter serialization), iterate.

Notes & caveats:
- This is backward-incompatible by design. Expect issues with any dependency that used the vulnerable API.
- If a fork is not viable long-term, coordinate with the Solana team to upgrade their `ed25519` adoption to 2.x.

What I can do next:
- Create a small script to find local uses of vulnerable ed25519 APIs (see `scripts/check_ed25519_usage.sh`).
- Draft a PR template and branch instructions you can use to push a backport to your fork.

If you want me to attempt the backport locally I can make a first pass on `v1-backport-security` branch changes in a local environment and test; however to publish the fork you'll need to open the repo on your GitHub fork and update `Cargo.toml` accordingly.
