<!-- A.B.C is the latest tag on develop: `git describe --tags --abbrev=0 origin/develop`. -->

## Summary

<!-- A few bullets with what operators and applications must know, bold lead, PR numbers in brackets. Skip what Breaking changes already says. The full PR list is appended by GitHub when the release is published. -->

- **Area:** what changed and what it means for users (#…)

## Breaking changes

<!-- Same types and rules as in a regular PR: tick `None` or every type that applies, with what breaks and what users must do. Unticked lines are stripped from the release notes. -->

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
- [ ] Only `Cargo.toml` and `Cargo.lock` change
- [ ] The description and diff of every PR merged since A.B.C reviewed, and every breaking change listed above, including ones a PR's own section left out: `git log A.B.C..origin/develop --format=%s | grep -o '#[0-9]*)$' | tr -d ')'`
- [ ] If Prod Compatibility Tests failed on this PR, Node–Node above says why

<!-- After merging: tag, publish the release and promote to testnet, see doc/releasing.md. -->
