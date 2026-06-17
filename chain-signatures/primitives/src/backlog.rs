use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{Chain, SignId};

/// Transaction information tracked across checkpoints.
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct PendingTx {
    pub sign_id: SignId,
    #[serde(with = "serde_bytes")]
    pub transaction: Vec<u8>,
}

impl fmt::Debug for PendingTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingTx")
            .field("sign_id", &self.sign_id)
            .finish()
    }
}

/// A checkpoint represents the backlog state at a specific block height.
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct Checkpoint {
    pub chain: Chain,
    pub block_height: u64,
    pub pending_requests: Vec<PendingTx>,
}

impl Checkpoint {
    pub fn empty(chain: Chain) -> Self {
        Self {
            chain,
            block_height: 0,
            pending_requests: Vec::new(),
        }
    }
}
