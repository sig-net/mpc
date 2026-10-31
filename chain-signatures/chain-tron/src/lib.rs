//! Tron chain integration for the MPC node. Tron is a bidirectional
//! execution *target*, not a source chain: this crate broadcasts
//! transactions from signed intents and confirms execution by polling txID
//! receipts on the solidity endpoint. The transaction wire format itself —
//! messages, canonical parse, signing derivations, addresses — lives in
//! [`mpc_tron_wire`].

mod client;
mod config;
mod types;
mod watcher;

pub use client::{SolidifiedNowBlock, TronHttp};
pub use config::TronConfig;
pub use types::{BroadcastOutcome, TronExecutionResult, TronLog, TronReceipt};
pub use watcher::TronWatcher;
