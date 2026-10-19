# Contributing

## Pull requests

- Branch off `develop` and open the PR against `develop`.
- PR titles follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat`, `fix`, `chore`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `revert`, `style`). CI checks the title, and it becomes the squash commit message.
- Fill in the **Breaking changes** section of the PR template: tick `None`, or every type that applies with what breaks and what users must do. This text goes into the release notes.
- Mark breaking PRs with `!` in the title, e.g. `feat(node)!: ...`.
- Network–Applications changes must be additive: new flows only, never a change to an existing one.
- Non-trivial changes start with a design doc under [`doc/`](doc/), and the PR updates it if the design changes.
- Large new features or behavior changes go behind the `unstable` feature flag until they are ready.

## Branches

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

`testnet` and `mainnet` only allow merge commits. A merge commit keeps the `develop` commits with their original SHAs; squash and rebase merges create copies instead. Keeping the originals means:

- The merge base moves forward, so each promotion PR shows only what is new since the last one. With copies, every promotion PR shows all past commits again and conflicts with the previous ones.
- `git branch -r --contains <sha>` tells you whether a `develop` commit is on testnet or mainnet.
- `git log` and `git bisect` on `testnet` can trace a regression to a single PR.

## Versioning

We use [semantic versioning](https://semver.org/). The version is `version` under `[workspace.package]` in the root `Cargo.toml`. Tags are the bare version, e.g. `1.21.0`.

A release is tagged when it first reaches `testnet`, or `mainnet` for a mainnet hotfix:

- Normal release: the release commit on `develop`, which `promote/X.Y.Z` points at, not the merge commit on `testnet`. The release commit is on `develop`, `testnet` and later `mainnet`.
- Hotfix: the merge commit of the hotfix PR on `testnet` or `mainnet`. It includes anything else merged to the branch since the hotfix branch was cut.

Promotion to mainnet does not create a new tag.

## Releasing

To release version `X.Y.Z`, do these three steps in order:

1. [Cut the release](#step-1-cut-the-release) on `develop`.
2. [Promote to testnet](#step-2-promote-to-testnet).
3. [Promote to mainnet](#step-3-promote-to-mainnet) once the release is signed off on testnet.

Only one release is in flight at a time: start the next release after the current one reaches `mainnet`. Until then, `testnet` only receives [hotfixes](#hotfixes).

### Step 1: Cut the release

1. Open a PR against `develop` titled `feat: release X.Y.Z` that bumps the workspace version and `Cargo.lock`. This is the **release PR**.
2. Merge it. Its squash commit on `develop` is the **release commit**; the merged PR shows it as "merged commit `<sha>` into `develop`".

### Step 2: Promote to testnet

1. Push a `promote/X.Y.Z` branch at the release commit, the squash commit of the release PR on `develop` from step 1. At this point it is only on `develop`, not on `testnet`. Commits merged to `develop` after it wait for the next release:
   ```sh
   git fetch origin
   git branch -r --contains <release-commit>   # lists origin/develop
   git push origin <release-commit>:refs/heads/promote/X.Y.Z
   ```
2. Open a PR from `promote/X.Y.Z` to `testnet` titled `chore: release X.Y.Z to testnet` and merge it with a merge commit. Don't open it from `develop`: the PR would pick up anything merged to `develop` while it is open. If `testnet` has a hotfix version bump that conflicts, keep the release's version.
3. Tag the release commit on `develop`, the same commit as in 1, not the merge commit on `testnet`:
   ```sh
   git tag X.Y.Z <release-commit> && git push origin X.Y.Z
   ```

### Step 3: Promote to mainnet

1. Push a `promote/X.Y.Z-mainnet` branch at the `testnet` commit that was signed off. Anything merged to `testnet` after it waits for its own decision:
   ```sh
   git fetch origin
   git push origin origin/testnet:refs/heads/promote/X.Y.Z-mainnet
   ```
2. Open a PR from `promote/X.Y.Z-mainnet` to `mainnet` titled `chore: release X.Y.Z to mainnet` and merge it with a merge commit. Never promote from `develop` or open the PR from `testnet` directly, so `mainnet` gets exactly what was signed off. If `mainnet` has a hotfix version bump that conflicts, keep the release's version.

## Hotfixes

Fixes land on `develop` first, then get cherry-picked downstream, so `develop` never loses a fix. The only exception is a bug that no longer exists on `develop` (see below). Each hotfix bumps the patch version of the release it fixes; `develop` never gets patch bumps.

### Bug in the release on testnet

For example, `testnet` has 1.21.0:

1. Merge the fix to `develop` as a normal PR. Call its squash commit `F`.
2. Branch off `testnet` and cherry-pick the fix. `-x` records `F` in the commit message, since the cherry-pick gets a new SHA:
   ```sh
   git fetch origin
   git switch -c hotfix/1.21.1 origin/testnet
   git cherry-pick -x F
   ```
3. Bump `version` under `[workspace.package]` in the root `Cargo.toml` to `1.21.1`, run `cargo check` to update `Cargo.lock`, and commit as `fix: release 1.21.1`.
4. Push the branch, open a PR to `testnet` titled `fix: hotfix 1.21.1 to testnet`, and merge it with a merge commit.
5. Right after merging, tag the merge commit:
   ```sh
   git fetch origin
   git tag 1.21.1 origin/testnet && git push origin 1.21.1
   ```

To find out whether a fix is on `testnet` or `mainnet`, search for its `develop` SHA: `git log origin/testnet --grep F`.

### Bug on mainnet

Same steps against `mainnet`: branch off `origin/mainnet`, bump the mainnet release's patch version (e.g. 1.20.0 to `1.20.1`), open the PR to `mainnet`, and tag `origin/mainnet` right after merging. This is the only way code reaches `mainnet` without going through `testnet`.

If the release on `testnet` has the same bug, hotfix it too, with its own patch version (e.g. `1.21.1`). Both branches then contain the fix, so the next promotion to `mainnet` only conflicts on the version; keep the release's version.

### When the cherry-pick doesn't apply

- If `develop` has changed the surrounding code, resolve the conflicts on the hotfix branch and point reviewers to `F` so they can compare.
- If the bug no longer exists on `develop`, write the fix directly on the hotfix branch and say why in the PR description. This is the only case where a fix skips `develop`.
