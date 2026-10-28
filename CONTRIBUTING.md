# Contributing

## Pull requests

- Branch off `develop` and open the PR against `develop`. How it reaches testnet and mainnet is in [Releasing](doc/releasing.md).
- PR titles follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat`, `fix`, `chore`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `revert`, `style`), with `!` before the colon if the PR has a breaking change. The title becomes the squash commit message.
- Fill in the [PR template](.github/pull_request_template.md). CI checks the **Breaking changes** section against the title and that the **Design** section has no placeholder left. Non-trivial changes start with a design doc under [`doc/`](doc/), and the PR updates it if the design changes.
- Large new features or behavior changes go behind a cargo feature of the node crate named `unstable-<name>`, off by default, until they are ready. Each unstable feature has its own flag so they can be enabled independently. Stabilizing means removing the flag.
