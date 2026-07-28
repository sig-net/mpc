// Should wrap B256 from Alloy, currently adding Alloy as a dependency pulls `alloy-sol-macro-input`, which requires Rust 1.85+
// TODO: Use B256 from Alloy once we can bump the minimum Rust version to 1.85+
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Copy)]
pub struct BidirectionalTxId(#[serde(with = "serde_bytes")] pub [u8; 32]);

pub type RespondBidirectionalSerializedOutput = Vec<u8>;
