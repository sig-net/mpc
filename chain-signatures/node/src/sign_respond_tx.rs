use alloy::primitives::B256;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SignRespondTxId(pub B256);

impl From<B256> for SignRespondTxId {
    fn from(b256: B256) -> Self {
        SignRespondTxId(b256)
    }
}

pub struct SignRespondTx {
    pub id: SignRespondTxId,
}
