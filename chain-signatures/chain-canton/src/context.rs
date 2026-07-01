use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(crate = "borsh")]
pub struct CantonChainCtx {
    pub sign_event_contract_id: String,
}
