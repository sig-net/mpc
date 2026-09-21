use std::time::Duration;

use mpc_chain_integration_core::utils::retry::SharedBackoff;
use near_fetch::ops::FunctionCallTransaction;
use near_fetch::result::ExecutionFinalResult;
use near_jsonrpc_client::errors::{JsonRpcError, JsonRpcServerError};
use near_jsonrpc_client::methods::send_tx::RpcTransactionError;
use near_primitives::errors::InvalidTxError;

/// First pause after a signer error; doubles on each repeat.
const SIGNER_PAUSE_BASE: Duration = Duration::from_secs(30);
/// Longest pause, so a fixed signer (e.g. topped up) resumes within this long.
const SIGNER_PAUSE_MAX: Duration = Duration::from_secs(300);

/// Gates shared by every NEAR RPC call the node makes: governance reads and
/// transactions, checkpoint votes, and signature responses.
#[derive(Clone)]
pub struct NearRpcGates {
    /// The NEAR endpoint's cooldown, extended on 429/402; every call waits it
    /// out (see `retry_rpc_gated!`).
    pub provider: SharedBackoff,
    /// Pauses this node's transactions after a signer error retrying cannot fix,
    /// such as insufficient balance. Reads are unaffected.
    signer: SharedBackoff,
}

impl NearRpcGates {
    pub fn new(provider: SharedBackoff) -> Self {
        Self {
            provider,
            signer: SharedBackoff::with_cooldowns(SIGNER_PAUSE_BASE, SIGNER_PAUSE_MAX),
        }
    }

    /// Fails without calling the RPC while transactions are paused.
    fn check_signer(&self) -> anyhow::Result<()> {
        let remaining = self.signer.remaining();
        if remaining.is_zero() {
            Ok(())
        } else {
            anyhow::bail!("NEAR transactions paused for {remaining:?} after a signer error")
        }
    }

    /// Submits `call` once, honoring the signer pause. Retries belong to the
    /// caller, so each attempt is one send and its error reaches the caller.
    pub async fn transact(
        &self,
        call: FunctionCallTransaction<'_>,
    ) -> anyhow::Result<ExecutionFinalResult> {
        self.check_signer()?;
        let result = call.transact().await;
        self.observe_transaction(&result);
        Ok(result?)
    }

    /// Records a transaction attempt's result on the signer pause.
    fn observe_transaction<T>(&self, result: &Result<T, near_fetch::Error>) {
        match result {
            Ok(_) => self.signer.report_success(),
            Err(err) if is_signer_error(err) => {
                let pause = self.signer.extend_cooldown();
                tracing::error!(%err, ?pause, "NEAR signer cannot transact; pausing transactions");
            }
            Err(_) => {}
        }
    }
}

/// Whether a transaction was rejected for a reason only fixing the signer
/// account resolves: insufficient balance, or a missing account or access key.
pub fn is_signer_error(err: &near_fetch::Error) -> bool {
    let near_fetch::Error::RpcTransactionError(err) = err else {
        return false;
    };
    matches!(
        &**err,
        JsonRpcError::ServerError(JsonRpcServerError::HandlerError(
            RpcTransactionError::InvalidTransaction {
                context: InvalidTxError::NotEnoughBalance { .. }
                    | InvalidTxError::LackBalanceForState { .. }
                    | InvalidTxError::InvalidAccessKeyError(_)
                    | InvalidTxError::SignerDoesNotExist { .. },
            }
        ))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_primitives::types::Balance;

    fn invalid_transaction(context: InvalidTxError) -> near_fetch::Error {
        near_fetch::Error::from(JsonRpcError::ServerError(JsonRpcServerError::HandlerError(
            RpcTransactionError::InvalidTransaction { context },
        )))
    }

    fn not_enough_balance() -> near_fetch::Error {
        invalid_transaction(InvalidTxError::NotEnoughBalance {
            signer_id: "node.testnet".parse().unwrap(),
            balance: Balance::from_yoctonear(1),
            cost: Balance::from_yoctonear(2),
        })
    }

    #[test]
    fn classifies_signer_errors() {
        assert!(is_signer_error(&not_enough_balance()));
        assert!(is_signer_error(&invalid_transaction(
            InvalidTxError::LackBalanceForState {
                signer_id: "node.testnet".parse().unwrap(),
                amount: Balance::from_yoctonear(1),
            }
        )));
        assert!(!is_signer_error(&invalid_transaction(
            InvalidTxError::InvalidNonce {
                tx_nonce: 1,
                ak_nonce: 2,
            }
        )));
        assert!(!is_signer_error(
            &near_fetch::Error::RpcReturnedInvalidData("not a signer error".into())
        ));
    }

    #[test]
    fn signer_error_pauses_transactions() {
        let gates = NearRpcGates::new(SharedBackoff::new());
        assert!(gates.check_signer().is_ok());

        gates.observe_transaction::<()>(&Err(not_enough_balance()));
        assert!(gates.check_signer().is_err());
        assert!(gates.provider.remaining().is_zero(), "reads stay open");
    }

    #[test]
    fn other_errors_do_not_pause_transactions() {
        let gates = NearRpcGates::new(SharedBackoff::new());
        gates.observe_transaction::<()>(&Err(invalid_transaction(InvalidTxError::InvalidNonce {
            tx_nonce: 1,
            ak_nonce: 2,
        })));
        assert!(gates.check_signer().is_ok());
    }
}
