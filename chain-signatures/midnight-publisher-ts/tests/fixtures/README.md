# Fixtures

Build tests need no chain captures: the singleton state is synthesized in-process from the installed `@sig-net/midnight-contract` (see `initialSingletonStateHex` in `tests/support.ts`) and populated with the installed verifier keys, matching the deployment path. This lets `buildIntent` verify that a same-named operation belongs to the contract version it was compiled against.

The one checked-in fixture, `initial-singleton-state.mn`, is the singleton's synthesized INITIAL state, written by `npm run gen:initial-state` (`devtools/gen-initial-state.ts`), never a chain capture: it is deterministic output of the installed `@sig-net/midnight-contract`. The guard test in `protocol.test.ts` compares it against the in-process synthesis, so any drift between the committed bytes and the synthesis fails loudly until the file is regenerated and recommitted, and the Rust differential test will read these same bytes as its `contract_state` input.
