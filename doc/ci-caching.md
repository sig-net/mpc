# CI rust-cache policy

This doc explains how `Swatinem/rust-cache` is wired across existing workflows.

## Constraints

- A GitHub Actions run can only restore caches saved on **its own branch** or on the
**default branch (`develop`)**. 
- Caches saved on PR branches or merge-queue refs
(`gh-readonly-queue/...`, unique per attempt) are invisible to every other run.

## Two entries

| Key | Contents | Size | Used by |
|---|---|---|---|
| `workspace-full` | dev tree **and** release `mpc-node` (both profiles) | ~2.2 GB | midnight, cluster-test, fixture-test, canton, nightly, prod-compat |
| `workspace-dev` | dev tree only | ~0.9 GB | unit, anvil tests, TS seam, deploy-dev-contract |

Two keys are required: with one shared key, the fastest saver on a fresh lockfile
hash would be a dev-only job, and its dev-only payload would leave every
release-building workflow cold (the entry is only written once per key).

## Who saves

- **Every successful run saves** its key. A save for an already-existing key is
  skipped by GitHub, so ordinary PRs (same lockfile as develop) upload nothing.
- **PR branches**: first push is cold and saves one entry on the branch;
  subsequent pushes restore it.
- **develop scope**: `midnight.yml` (full) and `unit.yml` (dev) also run on
  `push: develop` when `Cargo.lock` / `Cargo.toml` / `.cargo` / toolchain files
  **or the workflow's own file** change, and on `workflow_dispatch`. Changing
  the workflow file in the trigger list is what primes the entries after a
  policy change merges. Their entries are visible to *all* runs — new PRs'
  first pushes and every merge-queue run.

## Risk and failure modes

- Storage is capped at 10 GB, if exceeded, GitHub deletes the least-recently-used entries. Sometimes entry you need can get deleted, which will result in rebuild from scratch (currently +7-8 min)
