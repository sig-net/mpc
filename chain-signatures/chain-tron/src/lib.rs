//! Tron chain integration for the MPC node. Tron is a bidirectional
//! execution *target*, not a source chain: this crate assembles and
//! broadcasts transactions from signed intents and confirms execution by
//! polling txID receipts on the solidity endpoint.

mod address;
mod client;
mod config;
mod types;

pub use address::{parse_hex, ParseTronAddressError, TronAddress, TRON_ADDRESS_PREFIX};
pub use client::TronHttp;
pub use config::TronConfig;
pub use types::{AccountResources, BroadcastOutcome, NowBlock, TronLog, TronReceipt};
