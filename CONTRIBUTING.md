# Contributing

## Pull requests

- Branch off `develop` and open the PR against `develop`. How it reaches testnet and mainnet is in [Releasing](doc/releasing.md).
- Release and hotfix PRs use the templates in [`.github/PULL_REQUEST_TEMPLATE/`](.github/PULL_REQUEST_TEMPLATE/) instead of the default one, see [Releasing](doc/releasing.md#versioning).
- PR titles follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat`, `fix`, `chore`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `revert`, `style`). CI checks the title, and it becomes the squash commit message.
- Fill in the **Breaking changes** section of the [PR template](.github/pull_request_template.md): tick `None`, or every type that applies with what breaks and what users must do. This text goes into the release notes.
- Tick one option in the **Design** section of the PR template. Non-trivial changes start with a design doc under [`doc/`](doc/), and the PR updates it if the design changes.
- Large new features or behavior changes go behind a cargo feature of the node crate named `unstable-<name>`, off by default, until they are ready. Each unstable feature has its own flag so they can be enabled independently. Stabilizing means removing the flag.
