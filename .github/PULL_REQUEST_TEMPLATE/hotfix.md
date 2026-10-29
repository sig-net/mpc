<!-- A.B.C is the version in the branch's Cargo.toml: `git show origin/testnet:Cargo.toml | grep ^version`. The diff link resolves once X.Y.Z is tagged. -->

Bumps the workspace version from A.B.C to X.Y.Z on `testnet|mainnet`.
Full diff: https://github.com/sig-net/mpc/compare/A.B.C...X.Y.Z

## Summary

- **Area:** what was broken and what the fix does (#…, cherry-picked from `<sha>`; if the fix is only on this branch, say why)

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

- The fix (tick one):
  - [ ] is merged on `develop`
  - [ ] has no counterpart there because the bug no longer exists on `develop`, and the Summary says why
- [ ] Cherry-picked with `-x`
- [ ] Patch version bumped and `cargo check` run on this branch only; `develop` untouched
- [ ] The `regression` issue this closes, if any, is linked

<!-- After merging: tag and publish the release, then hotfix the other branch if it has the bug, see doc/releasing.md. -->
