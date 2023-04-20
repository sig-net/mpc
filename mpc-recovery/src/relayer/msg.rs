use near_primitives::{
    delegate_action::SignedDelegateAction,
    types::AccountId,
    views::{ExecutionOutcomeWithIdView, FinalExecutionStatus},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterAccountRequest {
    pub account_id: AccountId,
    pub allowance: u64,
    pub oauth_token: String,
}

pub type SendMetaTxRequest = SignedDelegateAction;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendMetaTxResponse {
    pub message: String,
    pub status: FinalExecutionStatus,
    #[serde(rename = "Transaction Outcome")]
    pub transaction_outcome: ExecutionOutcomeWithIdView,
    #[serde(rename = "Receipts Outcome")]
    pub receipts_outcome: Vec<ExecutionOutcomeWithIdView>,
}