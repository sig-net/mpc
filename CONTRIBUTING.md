# Contributing

## Pull requests

- Branch off `develop` and open the PR against `develop`. How it reaches testnet and mainnet is in [Releasing](doc/releasing.md).
- PR titles follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat`, `fix`, `chore`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `revert`, `style`). CI checks the title, and it becomes the squash commit message.
- Fill in the **Breaking changes** section of the [PR template](.github/pull_request_template.md): tick `None`, or every type that applies with what breaks and what users must do. This text goes into the release notes.
- Tick one option in the **Design** section of the PR template. Non-trivial changes start with a design doc under [`doc/`](doc/), and the PR updates it if the design changes.
- Large new features or behavior changes go behind a cargo feature of the node crate named `unstable-<name>`, off by default, until they are ready. Each unstable feature has its own flag so they can be enabled independently. Stabilizing means removing the flag.

## Documentation

These rules apply to the pages under [`doc/`](doc/).

- Constants, types and states appear as in the code, in backticks (`MAX_OUTBOX_PAYLOAD_LIMIT`, `ReservedKind::Using`), not paraphrased.
- What is not implemented is marked: design options sit under a heading that says so, and a gap names the issue or PR that tracks it.
- Don't copy lists the code already produces. Flags, env vars and metrics are in `--help` and `/metrics`; the doc says where to look and explains only what that output does not (sources, precedence, semantics).
- Diagrams are Mermaid, not generated images.
- A term is defined once, in the doc that introduces it, and other pages link to that definition. The [glossary](doc/glossary.md) collects all terms. Protocol actors are nodes, not parties.
- A property is stated once, in the doc of the mechanism that enforces it. Its ID is local to that doc; another doc cites it with the doc's name and a link (checkpoints S1).
- It is good practice for a design doc to mention the alternatives it considered and why they were rejected.

### Structuring a page

There is no fixed template. Pick what suits the page; these docs are good models:

- [checkpoints.md](doc/checkpoints.md) and [bidirectional-calls.md](doc/bidirectional-calls.md) for a new mechanism or anything with a safety argument: entities and vocabulary, interfaces, assumptions, properties, the design, why the properties hold, limits.
- [posit-state-machine.md](doc/posit-state-machine.md) for existing code that is a state machine: Mermaid diagrams state by state, then invariants.

What helps:

- A TL;DR and a short map of the sections for a long page.
- An opening that names the code the page describes and says whether it describes the implementation or a design.
- Assumptions before the properties that rest on them.
