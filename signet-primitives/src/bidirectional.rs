#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Copy)]
pub struct BidirectionalTxId(#[serde(with = "serde_bytes")] pub [u8; 32]);

pub type RespondBidirectionalSerializedOutput = Vec<u8>;
