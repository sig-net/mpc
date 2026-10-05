//! Tron chain integration for the MPC node.
//!
//! Tron is a bidirectional execution *target*, not a source chain: there is
//! no ChainSignatures contract on Tron and nothing to index. Midnight is the
//! source; this crate assembles and broadcasts transactions from signed
//! intents, then confirms execution by polling txID receipts on the
//! solidity endpoint.

mod config;

pub use config::TronConfig;
