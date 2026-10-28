<!-- A.B.C is the latest tag on develop: `git describe --tags --abbrev=0 origin/develop`. The diff link resolves once X.Y.Z is tagged. -->

Bumps the workspace version from A.B.C to X.Y.Z.
Full diff: https://github.com/sig-net/mpc/compare/A.B.C...X.Y.Z

## Summary

<!-- One bullet per area, bold lead, PR numbers in brackets. Drop empty areas. -->

- **Area:** what changed and what it means for users (#…)

## Breaking changes

<!-- Tick `None` or every type that applies, with what breaks and what users must do. Unticked lines can stay or go; they are stripped from the release notes. -->

- [ ] None
- [ ] **Node–Node:** …
- [ ] **Contract–Node:** …
- [ ] **Contract state:** …
- [ ] **Network–Applications:** …
- [ ] **Operator** (flags, env vars, config, storage migration): …

## Checklist

<!-- Everything from here on is stripped from the release notes. -->

- The release soaking on `testnet` (tick one):
  - [ ] was promoted to `mainnet` first
  - [ ] is replaced by this one and never reaches `mainnet` because: [out of schedule / regression #…]
- [ ] Version bumped in the root `Cargo.toml` and `cargo check` run; only `Cargo.toml` and `Cargo.lock` change
- [ ] Every PR merged since A.B.C reviewed and its Breaking changes copied above: `git log A.B.C..origin/develop --format=%s | grep -o '#[0-9]*)$' | tr -d ')'`
- Prod Compatibility Tests on this PR (tick one):
  - [ ] passed
  - [ ] failed, and Node–Node above explains why
- [ ] A pass over the diffs and descriptions of the merged PRs found no breaking change missing above, including ones a PR's own section left out; disagreements settled with the PR authors

<!-- After merging: tag, publish the release and promote to testnet, see doc/releasing.md. -->
