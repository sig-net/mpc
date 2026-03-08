## Goal
Propose a *simple* design to reduce complexity as we add more indexers/chains
## Context
* Indexers are getting complex as we add chains
* Each indexer is started as its own task from `Cli::Start`
* RPC is currently a *single* task shared across all indexers, using an enum over clients
* RPC logic should eventually live alongside the indexer for each chain, but that migration can happen later
## Problem
* Current structure will not scale cleanly as we add more integrations
* We need abstractions *now* to avoid compounding complexity
## Proposed direction (challenge this if needed)
* Define a common client interface
* Implement a concrete client per chain (indexer + RPC)
* Interact with all chains through the shared interface
* Eventually unify indexer clients and RPC clients behind the same abstraction
## Constraints / Notes
* Do **not** implement anything yet — design only
* Optimize for the *simplest possible* approach that scales
* We already support: Hydration, Ethereum, Solana
* We know at least one more integration is coming
* NEAR (`indexer.rs`) can be ignored for this refactor (testing-only)
* Push back if this approach is flawed after reviewing more of the codebase
* Ask clarifying questions where necessary
## Deliverable
* A clear, minimal design proposal for the abstraction and flow