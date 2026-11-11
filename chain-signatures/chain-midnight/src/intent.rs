//! One respond call as the publisher hands it to the intent client, and what a
//! finalized submit answers.

use minocrab_publisher::{Attestation, EcdsaSignature};

/// A finalized transaction and the funding wallet's DUST before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Submitted {
    pub tx_id: String,
    /// Spendable DUST in SPECK.
    pub dust_balance: u128,
}

/// One respond call, typed as the circuits take it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IntentRequest {
    pub circuit: RespondCircuit,
    pub contract_address: [u8; 32],
    pub request_id: [u8; 32],
    pub signature: EcdsaSignature,
    /// The reads this caller pinned, so the build is a pure function of them.
    pub contract_state: Vec<u8>,
    pub ledger_parameters: Vec<u8>,
    /// Absolute unix seconds, not a duration from now.
    pub ttl_seconds: u64,
}

/// The responder circuit a call proves, with the arguments only it takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RespondCircuit {
    Respond,
    RespondBidirectional(Attestation),
}

impl RespondCircuit {
    /// The circuit's name in the contract and in the packaged keys.
    pub(crate) const fn name(&self) -> &'static str {
        match self {
            Self::Respond => "respond",
            Self::RespondBidirectional(_) => "respondBidirectional",
        }
    }
}
