<!-- A.B.C is the version in the branch's Cargo.toml: `git show origin/testnet:Cargo.toml | grep ^version`. The diff link resolves once X.Y.Z is tagged. -->

Bumps the workspace version from A.B.C to X.Y.Z on `testnet|mainnet`.
Full diff: https://github.com/sig-net/mpc/compare/A.B.C...X.Y.Z

## Summary

<!--
What was broken and what the fix does, with the develop commit it was
cherry-picked from. If the fix is only on this branch, say why.
-->

- **Area:** what was broken and what the fix does (#…, cherry-picked from `<sha>`)

## Breaking changes

<!-- `None`, or each type that applies with what breaks and what users must do. -->

- None
- **Node–Node:** …
- **Contract–Node:** …
- **Contract state:** …
- **Network–Applications:** …
- **Operator** (flags, env vars, config, storage migration): …

## Checklist

<!-- Everything from here on is stripped from the release notes. -->

- [ ] Fix merged on `develop`, or the Summary says why the bug no longer exists there
- [ ] Cherry-picked with `-x`
- [ ] Patch version bumped and `cargo check` run on this branch only; `develop` untouched
- [ ] The `regression` issue this closes, if any, is linked
- [ ] Title is `fix: hotfix X.Y.Z to testnet` or `fix: hotfix X.Y.Z to mainnet`

<!-- After merging: tag and publish the release, then hotfix the other branch if it has the bug, see doc/releasing.md. -->
