# Project Signet MPC (Multi-Party Computation)
## Skill
/caveman ultra
## Overview
Read doc/ARCHITECTURE.md or doc/mpc_node_specification.md for overview
### Context
- Project enables communication across chains via direct transactions
- High level pieces:
  - contract: chain source of sign requests
  - indexer: chain indexer that parses sign requests
  - MPC node: signs transaction payload for target chain from source chain
- Supports ethereum, solana and hydration
- integration-tests:
  - redis used as storage for triples and presignatures
  - deploys near contract for governance/state
  - set of MPC nodes (usually 3) spunned to do all work
- sign request flow:
  - `sign`/`sign_bidirectional` called on source chain contract
  - source chain indexer sees the sign request; sent to the MPC node
  - MPC signing protocol signs with other MPC nodes
  - on signed, RPC publishes signature to the source chain
  - receives published signature; user/contract verifies the signature
    - user can do what they want with the signature (not our problem)
  - if sign request is `sign_bidirectional`, user submits the transaction with the signature to the target chain
    - note, user needs to fund the derived account for gas fees on the target chain
  - target chain indexer watches execution and then do another signature request on the execution complete
  - MPC node will do the signing protocol again to sign the execution transaction
  - RPC will publish the signed execution transaction to source chain via `respond_bidirectional`
  - user receives the published execution signature
### Practices
- No `git commit`, use `git` to analyze diffs/history
- Follow/utilize TDD cycle
- No `cd` into subdirectories to run tests: run tests from repo root, supply `-p <package-name>` to `cargo test` to run tests for crate.
- For something beyond unit tests, but not integration tests, utilize MpcFixture (aka component tests). Examples: `integration-tests/tests/cases/mpc.rs`. integration tests are long running and expensive.
- Never run integration tests in parallel or all of them at once. Only run one at a time. Integration tests should be run with `--nocapture` to see all logs
- If redis is required for any tests, put the test in `integration-tests`
- Implement proper error handling as needed when inside `chain-signatures/node` but don't worry about it in `integration-tests`
- if scripting work needed, prefer using `python3`
- use `rg` over `grep`
## Style Guide
Produce idiomatic, maintainable, and readable Rust code aligning with modern best practices
### Core Principles
* Prefer clarity over cleverness.
* Keep functions small and focused.
* Avoid deep nesting (maximum 2 levels).
* Follow the *happy path* using early returns.
* Favor compile-time guarantees over runtime checks.
### Control Flow & Readability
#### Avoid Deep Nesting
* Do not exceed 2 levels of indentation.
* Refactor nested logic into helper functions.
**Bad:**
```rs
if cond1 {
    if cond2 {
        if cond3 {
            do_work();
        }
    }
}
```
**Good:**
```rs
if !cond1 || !cond2 || !cond3 {
    return;
}

do_work();
```
#### Prefer Early Returns
* Handle error cases immediately.
* Keep the main logic path linear and easy to follow.
**Example:**
```rs
fn process(input: &str) -> Result<Output, Error> {
    if input.is_empty() {
        return Err(Error::Empty);
    }

    let parsed = parse(input)?;

    if !parsed.is_valid() {
        return Err(Error::Invalid);
    }

    Ok(build(parsed))
}
```
### Error Handling
* Use `Result` and `?` for propagation.
* Avoid `unwrap()` and `expect()` in production code.
* Define domain-specific error types.
* Prefer `thiserror` for error enums.
### Ownership & Borrowing
* Prefer borrowing (`&T`, `&mut T`) over ownership when possible.
* Avoid unnecessary cloning.
* Use `Cow` when flexibility between owned and borrowed data is needed.
### Struct Construction Patterns
#### Builder Pattern
Use builders for structs with:
* Many fields
* Optional configuration
* Complex initialization
**Example:**
```rust
let config = Config::builder()
    .host("localhost")
    .port(8080)
    .timeout(Duration::from_secs(5))
    .build()?;
```
Guidelines:
* Builder methods should take `self` and return `Self`.
* Use method chaining.
* Validate in `build()`.
#### Typestate Pattern
Use typestate to enforce correctness at compile time when:
* Order of operations matters
* Certain fields must be set before use
**Example:**
```rs
struct Uninitialized;
struct Initialized;

struct Client<State> {
    inner: Inner,
    _state: PhantomData<State>,
}

impl Client<Uninitialized> {
    fn init(self) -> Client<Initialized> {
        Client {
            inner: self.inner.init(),
            _state: PhantomData,
        }
    }
}

impl Client<Initialized> {
    fn send(&self) {
        // safe to use
    }
}
```
Guidelines:
* Encode invariants in types.
* Prevent invalid states from compiling.
### Traits & Abstractions
* Prefer traits over generics when behavior matters.
* Keep traits small and composable.
* Avoid overly generic abstractions.
### Async Code
* Use `async`/`await` idiomatically.
* Avoid blocking calls in async contexts.
* Prefer `tokio` primitives when applicable.
### Iterators & Functional Style
* Prefer iterator adapters over manual loops.
**Example:**
```rs
let sum: i32 = values
    .iter()
    .filter(|v| **v > 0)
    .map(|v| v * 2)
    .sum();
```
### Module Organization
* Keep modules small and cohesive.
* Avoid large files (>500 lines when possible).
* Use `mod.rs` or flat modules consistently.
### Naming Conventions
* Use descriptive names.
* Avoid abbreviations unless widely understood.
* Regular function names should be 3 words max.
* Test function names can be as descriptive as needed
### Testing
* Write unit tests alongside code.
* Prefer small, focused tests.
* Test behavior, not implementation details.
### Performance Guidelines
* Avoid premature optimization.
* Measure before optimizing.
* Use zero-cost abstractions where possible.
### Anti-Patterns to Avoid
* Deeply nested control flow
* Excessive cloning
* Large, monolithic functions
* Overuse of generics without clear benefit
* Runtime validation when compile-time guarantees are possible
### Summary Checklist
Before submitting code, ensure:
* [ ] No more than 2 levels of nesting
* [ ] Early returns used for error handling
* [ ] Happy path is clear and linear
* [ ] Builder pattern used where appropriate
* [ ] Typestate used for critical invariants
* [ ] No `unwrap()` in production
* [ ] Minimal cloning
* [ ] Idiomatic iterator usage
## Agents
* `/caveman ultra` skill where possible
* Git commit unit of work according to tasks list