//! The funding wallet: the DUST that pays every respond transaction's fee.
//!
//! Spendable DUST is derived by replaying the ledger's DUST events into a
//! `DustLocalState`, the same state the Midnight wallet SDK keeps; no node RPC serves
//! it. The state lives in memory. A checkpoint of it, kept in the node's store, lets a
//! restart resume the replay instead of starting it over from the first event.
//!
//! The wallet never adopts the pending marks `DustLocalState::spend` sets on its
//! scratch copy. It reserves the UTXOs a submitted transaction spends instead, and a
//! reservation ends when the chain spends them, when the transaction is refused, never
//! sent, or seen expired, or a minute after the transaction's TTL, by when it has
//! landed or never will.

mod checkpoint;
mod keys;
mod sync;
mod wallet;

#[cfg(test)]
mod live;
#[cfg(test)]
pub(crate) mod tests;

pub use checkpoint::{Checkpoint, DustCheckpointStore, CHECKPOINT_INTERVAL};
pub use keys::{dust_secret_key, owner_of, parse_seed};
pub use sync::{
    apply, event_hash, is_ledger_8_event, keep_checkpoint, resume_from, start_over, Shared, Synced,
    RESTORE_STRIKES, RESTORE_STUCK_TIMEOUT, RESUBSCRIBE_DELAY, RESUME_TIMEOUT, STALL_GRACE,
};
pub use wallet::{
    dust_deficit, plan_fee, FeePayer, FeePlan, FundingWallet, Reservation, SealedTx, UnprovenTx,
};
