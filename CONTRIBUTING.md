# Contributing

## Pull requests

- Branch off `develop` and open the PR against `develop`.
- PR titles follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat`, `fix`, `chore`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `revert`, `style`). CI checks the title, and it becomes the squash commit message.
- Fill in the **Breaking changes** section of the [PR template](.github/pull_request_template.md): tick `None`, or every type that applies with what breaks and what users must do. This text goes into the release notes.
- Tick one option in the **Design** section of the PR template. Non-trivial changes start with a design doc under [`doc/`](doc/), and the PR updates it if the design changes.
- Large new features or behavior changes go behind a cargo feature of the node crate named `unstable-<name>`, off by default, until they are ready. Each unstable feature has its own flag so they can be enabled independently. Stabilizing means removing the flag.

## Branches

[GitLab flow](https://about.gitlab.com/topics/version-control/what-is-gitlab-flow/) with environment branches and upstream-first hotfixes:

```
feature/* ──PR──► develop ──► testnet ──► mainnet
```

| Branch    | Contains                         |
|-----------|----------------------------------|
| `develop` | Integration branch; all PRs land here |
| `testnet` | The release on testnet           |
| `mainnet` | The release on mainnet           |

Code moves downstream only.

`testnet` and `mainnet` are protected: nobody can push to them directly, admins included. They change only by merging a PR, either a promotion PR or a hotfix cherry-pick PR.

`develop` only allows squash merges, through the merge queue, so each PR becomes a single commit.

`testnet` and `mainnet` only allow merge commits. A merge commit keeps the `develop` commits with their original SHAs, so git knows they are already on the branch and each promotion PR shows only what is new. Squash or rebase merges would create copies, and every promotion PR would show all past commits again and conflict with them.

## Versioning

We use [semantic versioning](https://semver.org/). The version is `version` under `[workspace.package]` in the root `Cargo.toml`. Tags are the bare version, e.g. `1.21.0`.

Every tag has a GitHub release whose notes are the PR description. Release and hotfix PRs replace the template body with **Summary**, and **Breaking changes** (`None`, or each with its type and required action). Right after the PR merges:

```sh
git tag X.Y.Z <commit> && git push origin X.Y.Z
gh pr view <pr> --json body --jq .body | gh release create X.Y.Z --verify-tag --notes-file -
```

- Release: the commit is the release commit on `develop`, the PR is the release PR.
- Hotfix: the commit is the merge commit of the hotfix PR on `testnet` or `mainnet`, the PR is the hotfix PR.

Promotion to testnet or mainnet does not create a tag.

## Releasing

Every second Tuesday is a **release day**. On it, in this order:

1. [Promote to mainnet](#step-1-promote-to-mainnet) the release that soaked on testnet.
2. [Cut the next release](#step-2-cut-the-release) on `develop`.
3. [Promote it to testnet](#step-3-promote-to-testnet).
4. [Soak](#step-4-soak) it there until the next release day.

### Step 1: Promote to mainnet

1. Push a `promote/X.Y.Z-mainnet` branch at the `testnet` commit that finished the soak:
   ```sh
   git fetch origin
   git switch -c promote/X.Y.Z-mainnet origin/testnet
   git push origin promote/X.Y.Z-mainnet
   ```
2. Open a PR from `promote/X.Y.Z-mainnet` to `mainnet` titled `chore: release X.Y.Z to mainnet` and merge it with a merge commit. Never promote from `develop` or open the PR from `testnet` directly, so `mainnet` gets exactly what was soaked. If the version line conflicts with a hotfix bump, take the version from the promote branch.

### Step 2: Cut the release

1. Open a PR against `develop` titled `chore: release X.Y.Z` that bumps the version and runs `cargo check` to update `Cargo.lock`.
2. Write the release notes in its description, collecting the Breaking changes sections of the merged PRs.
3. Merge it. The squash commit on `develop` is the **release commit**; the PR page shows its SHA.
4. Tag the release commit and publish the GitHub release, see [Versioning](#versioning).

### Step 3: Promote to testnet

1. Push a `promote/X.Y.Z` branch at the tag. Commits merged to `develop` after the release commit wait for the next release:
   ```sh
   git fetch origin
   git switch -c promote/X.Y.Z X.Y.Z
   git push origin promote/X.Y.Z
   ```
2. Open a PR from `promote/X.Y.Z` to `testnet` titled `chore: release X.Y.Z to testnet` and merge it with a merge commit. Don't open it from `develop`: the PR would pick up anything merged to `develop` while it is open. If the version line conflicts with a hotfix bump, take the version from the promote branch.

### Step 4: Soak

The release stays on testnet until the next release day, at least 7 days. It is ready for mainnet when no open issue labeled `regression` points at it. Anyone who sees a regression on testnet, from alerts, dashboards or reports, opens such an issue. A [hotfix](#hotfixes) closes it and restarts the 7 days.

Out-of-schedule releases to `testnet` are possible but discouraged. If a feature cannot wait, cut a release and promote it to `testnet`; it replaces the soaking release, which never reaches `mainnet`. This restarts the 7 days and can postpone the mainnet promotion by up to 7 days.

## Hotfixes

Fixes land on `develop` first, then get cherry-picked downstream, so `develop` never loses a fix. The only exception is a bug that no longer exists on `develop` (see below). Each hotfix bumps the patch version of the release it fixes; `develop` never gets patch bumps.

### Bug on testnet

For example, `testnet` has 1.21.0:

1. Merge the fix to `develop` as a normal PR.
2. Branch off `testnet` and cherry-pick the fix. `-x` records the original commit in the message, since the cherry-pick gets a new SHA:
   ```sh
   git fetch origin
   git switch -c hotfix/1.21.1 origin/testnet
   git cherry-pick -x <fix-commit>
   ```
3. Bump the version to `1.21.1`, run `cargo check` to update `Cargo.lock`, and commit as `fix: release 1.21.1`.
4. Push the branch, open a PR to `testnet` titled `fix: hotfix 1.21.1 to testnet` with release notes in the description, and merge it with a merge commit.
5. Tag the merge commit and publish the GitHub release, see [Versioning](#versioning).

If `mainnet` has the same bug and it cannot wait for the next release day, hotfix it too, as below.

### Bug on mainnet

Same steps against `mainnet`, with the mainnet release's patch version, e.g. 1.20.0 to `1.20.1`.

Then hotfix `testnet` the same way, with its own patch version (e.g. `1.21.1`), unless the release there already contains the fix. Otherwise the next promotion would bring the bug back to `mainnet`. With both branches fixed, the next promotion only conflicts on the version line; take the version from the promote branch, `1.21.1`.

### When the cherry-pick doesn't apply

- If `develop` has changed the surrounding code, resolve the conflicts on the hotfix branch and point reviewers to the `develop` commit so they can compare.
- If the bug no longer exists on `develop`, write the fix directly on the hotfix branch and say why in the PR description.
