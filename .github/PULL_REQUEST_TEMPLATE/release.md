Bumps the workspace version from A.B.C to X.Y.Z.
Full diff: https://github.com/sig-net/mpc/compare/A.B.C...X.Y.Z

## Summary

<!--
One bullet per area, bold lead, PR numbers in brackets. Drop empty areas.
Example: https://github.com/sig-net/mpc/pull/1395
-->

- **Area:** what changed and what it means for users (#…)

## Breaking changes

<!--
Collect the Breaking changes sections of the merged PRs. Keep `None` or the
types that apply; for each, what breaks and what users must do.
-->

- None
- **Node–Node:** A.B.C and X.Y.Z nodes handle some requests differently, so while both versions run those requests may not complete:
  - …
- **Contract–Node:** …
- **Contract state:** …
- **Network–Applications:** …
- **Operator** (flags, env vars, config, storage migration): …

## Checklist

<!-- Everything from here on is stripped from the release notes. -->

- [ ] The release on `testnet` was promoted to `mainnet`, or this release replaces it and it never reaches `mainnet` because: [out of schedule / regression #…]
- [ ] Version bumped in the root `Cargo.toml` and `cargo check` run; only `Cargo.toml` and `Cargo.lock` change
- [ ] Title is `chore: release X.Y.Z`
- [ ] Every PR merged since A.B.C reviewed and its Breaking changes copied above: `gh pr list --state merged --base develop --search "merged:>YYYY-MM-DD" --limit 200`
- [ ] Prod Compatibility Tests passed on this PR, or the failure is explained under Node–Node
- [ ] A pass over the diffs of the merged PRs found no breaking change missing above; disagreements settled with the PR authors

<!-- After merging: tag, publish the release and promote to testnet, see doc/releasing.md. -->
