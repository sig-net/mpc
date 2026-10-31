//! One respond call as the publisher hands it to the intent client, and the marker
//! on an error whose transaction may still land.

/// A submit whose outcome is unknown: the transaction may still land.
#[derive(Debug)]
pub(crate) struct AmbiguousSubmit;

impl std::fmt::Display for AmbiguousSubmit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "the transaction was not seen finalized; it may still land, and a later publisher retry \
             may post the response again",
        )
    }
}

impl std::error::Error for AmbiguousSubmit {}

#[cfg(test)]
pub(crate) fn is_ambiguous_submit(error: &anyhow::Error) -> bool {
    error.downcast_ref::<AmbiguousSubmit>().is_some()
}

/// A finalized transaction and the funding wallet's DUST before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Submitted {
    pub tx_id: String,
    /// Spendable DUST in SPECK.
    pub dust_balance: u128,
}

/// One respond call. Every byte field is bare lowercase hex with no `0x`; the builder
/// converts nothing and rejects anything else.
#[derive(Debug, Clone, PartialEq)]
pub struct IntentRequest {
    /// `respond` or `respondBidirectional`.
    pub circuit: &'static str,
    pub contract_address: String,
    pub request_id: String,
    pub signature: WireSignature,
    pub attestation: Option<WireAttestation>,
    /// The reads this caller pinned, so the build is a pure function of them.
    pub contract_state: String,
    pub ledger_parameters: String,
    /// Absolute unix seconds, not a duration from now.
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WireSignature {
    pub big_r: WirePoint,
    pub s: String,
    /// 0 or 1.
    pub recovery_id: u8,
}

/// Decimal strings, as the attestation metadata carries the circuit's `Uint<64>` fields.
#[derive(Debug, Clone, PartialEq)]
pub struct WireAttestation {
    pub block_height: String,
    pub output_kind: u8,
    pub serialized_output_length: String,
    pub output_hash: String,
    pub digest: String,
}

/// SEC1 big-endian affine coordinates, reaching the ledger untouched.
#[derive(Debug, Clone, PartialEq)]
pub struct WirePoint {
    pub x: String,
    pub y: String,
}
