Hotfix X.Y.Z for X.Y.0 on `testnet|mainnet`.

## Summary

<!--
What was broken and what the fix does, with the develop commit it was
cherry-picked from. If the fix is only on this branch, say why.
-->

- **Area:** what was broken and what the fix does (#…, cherry-picked from <sha>)

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
- [ ] Patch version bumped on this branch only; `develop` untouched
- [ ] The `regression` issue this closes is linked
- [ ] Title is `fix: hotfix X.Y.Z to testnet` or `fix: hotfix X.Y.Z to mainnet`

<!-- After merging: tag and publish the release, then hotfix the other branch if it has the bug, see doc/releasing.md. -->
