# CI rust-cache policy

How `Swatinem/rust-cache` is wired across workflows.

## Cache scoping rules

- A run restores caches saved on **its own branch** or on **develop**. Caches
  saved on PR branches or merge-queue refs (`gh-readonly-queue/...`, unique per
  attempt) are invisible to every other run.
- Saves are per-scope: a PR run uploads its own copy of a key even if an
  identical entry exists on develop. Unchecked, that is ~3 GB per PR.
- Storage is capped at 10 GB (LRU eviction). A cold rebuild costs ~7–8 min.

## Entries

| Key | Contents | Size | Used by |
|---|---|---|---|
| `workspace-full` | dev tree + release `mpc-node` | ~3.3 GB | midnight, cluster-test, fixture-test, canton, nightly, prod-compat |
| `workspace-dev` | dev tree only | ~0.9 GB | unit, anvil tests, TS seam, deploy-dev-contract |

Two keys so a dev-only job can't claim a fresh key first and leave the
release-building workflows cold.

## Save policy

Every rust-cache call site uses:

```yaml
save-if: ${{ github.event_name != 'merge_group' &&
    (github.event_name != 'pull_request' || steps.depchange.outputs.changed == 'true') }}
```

preceded by a `depchange` step that diffs the PR against develop and sets
`changed=true` when any dependency-defining file is touched (`Cargo.lock`,
any `Cargo.toml`, `.cargo/**`, `rust-toolchain*`, `.github/workflows/*`).

- **merge_group**: never saves — merge-queue refs are unique per attempt.
- **pull_request**: saves only for dependency-changing PRs. Clean PRs restore
  from develop and upload nothing; dep-bump PRs keep a branch copy so their
  later pushes stay warm.
- **push (develop) / workflow_dispatch**: always save — this seeds the
  develop-scope entries. `midnight.yml` (full) and `unit.yml` (dev) trigger on
  `push: develop` when dependency files or their own workflow file change.

After a develop merge that changes `Cargo.lock`, PRs may run cold until the
seeding push completes; `workflow_dispatch` on midnight/unit re-seeds instantly.

## Troubleshooting

rust-cache's key embeds a hash of `rustc -vV`, `rustup toolchain list` and
`CARGO*`/`CC*`/`CMAKE*`/`RUST*` env vars, none of which are repo files. If
restores go cold without a lockfile change, check the rust-cache log for which
key it computed — a changed environment hash splits the key and causes junk
entries.
