//! Submit classification: where a submitted ledger transaction ended up and
//! why `author_submitExtrinsic` refused one.

use anyhow::Context as _;
use subxt::backend::legacy::rpc_methods::NumberOrHex;
use subxt::ext::codec::DecodeAll as _;
use subxt::ext::subxt_rpcs::{rpc_params, Error as RawRpcError};
use subxt::utils::H256;

use super::publisher_rpc::{recall, remember, MidnightPublisherRpc};
use super::statics::{TxApplied, TxPartialSuccess};
use crate::types::{BlockHash, LedgerTxHash};

/// Where a submitted ledger transaction ended up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Landing {
    Applied,
    /// Applied but for a fallible segment; readers still read its guaranteed events.
    PartialSuccess,
    /// A finalized block is past the transaction's TTL, so it can no longer land.
    Expired,
}

/// Why `author_submitExtrinsic` did not take a transaction.
#[derive(Debug)]
pub(crate) enum SubmitRefusal {
    /// The node answered with a refusal: nothing entered its pool.
    Refused(String),
    /// No answer arrived; the transaction may be in the pool.
    Unanswered(anyhow::Error),
    /// The transaction was never sent: the node's runtime could not be read.
    Unsent(anyhow::Error),
    /// The call is not in the node's runtime metadata: this node cannot carry
    /// the transaction, whatever its state.
    Mismatch(anyhow::Error),
}

/// The pool's "already imported" answer: the transaction is in it.
const ALREADY_IMPORTED: i32 = 1013;

/// A JSON-RPC error is the node's own refusal, so nothing entered its pool; a
/// transport failure leaves the transaction possibly in it.
fn classify_submit_reply(
    reply: Result<serde_json::Value, RawRpcError>,
) -> Result<(), SubmitRefusal> {
    match reply {
        Ok(_) => Ok(()),
        Err(RawRpcError::User(reply)) if reply.code == ALREADY_IMPORTED => Ok(()),
        Err(RawRpcError::User(reply)) => Err(SubmitRefusal::Refused(format!(
            "{}: {}{}",
            reply.code,
            reply.message,
            reply
                .data
                .map(|data| format!(" ({})", data.get()))
                .unwrap_or_default()
        ))),
        Err(error) => Err(SubmitRefusal::Unanswered(
            anyhow::Error::new(error).context("author_submitExtrinsic failed"),
        )),
    }
}

#[async_trait::async_trait]
impl crate::native::SubmitChain for MidnightPublisherRpc {
    async fn block_number(&self, at: &BlockHash) -> anyhow::Result<u64> {
        let header = self.header(H256::from(*at)).await?;
        Ok(u64::from(header.number))
    }

    async fn block_hash_at(&self, number: u64) -> anyhow::Result<Option<BlockHash>> {
        Ok(self
            .legacy
            .chain_get_block_hash(Some(NumberOrHex::Number(number)))
            .await
            .context("failed to fetch a midnight block hash by number")?
            .map(BlockHash::from))
    }

    async fn block_time(
        &self,
        at: &BlockHash,
    ) -> anyhow::Result<midnight_base_crypto::time::Timestamp> {
        // Named for its type: interpolating `at` must render the full hash, and an
        // H256 binding here once truncated that render to `0x4343…4343`.
        let at_h256 = H256::from(*at);
        if let Some(time) = recall(&self.blocks().times, at_h256) {
            return Ok(time);
        }
        let key = self
            .client_for_block(at_h256)
            .await?
            .storage()
            .address_bytes(&subxt::dynamic::storage(
                "Timestamp",
                "Now",
                Vec::<subxt::dynamic::Value>::new(),
            ))
            .context("the midnight runtime has no Timestamp::Now")?;
        let raw = self
            .legacy
            .state_get_storage(&key, Some(at_h256))
            .await
            .context("failed to fetch the midnight block time")?
            .with_context(|| format!("midnight node has no block time at {at}"))?;
        let millis =
            u64::decode_all(&mut &raw[..]).context("the midnight block time is not a u64")?;
        let time = midnight_base_crypto::time::Timestamp::from_secs(millis / 1000);
        remember(&mut self.blocks().times, at_h256, time);
        Ok(time)
    }

    async fn submit(&self, transaction: &[u8]) -> Result<(), SubmitRefusal> {
        let client = self
            .client_at(None)
            .await
            .map_err(|error| SubmitRefusal::Unsent(error.context("reading the node's runtime")))?;
        let extrinsic = client
            .tx()
            .create_unsigned(&subxt::dynamic::tx(
                "Midnight",
                "send_mn_transaction",
                vec![subxt::dynamic::Value::from_bytes(transaction)],
            ))
            .map_err(|error| {
                SubmitRefusal::Mismatch(
                    anyhow::Error::new(error)
                        .context("send_mn_transaction did not match the node's metadata"),
                )
            })?;
        let encoded = format!("0x{}", hex::encode(extrinsic.encoded()));
        classify_submit_reply(
            self.rpc
                .request::<serde_json::Value>("author_submitExtrinsic", rpc_params![encoded])
                .await,
        )
    }

    async fn landing(
        &self,
        at: &BlockHash,
        tx_hash: LedgerTxHash,
    ) -> anyhow::Result<Option<Landing>> {
        let at_h256 = H256::from(*at);
        let events = self
            .client_for_block(at_h256)
            .await?
            .events()
            .at(at_h256)
            .await
            .context("failed to fetch midnight block events")?;
        for event in events.iter() {
            let event = event.context("Midnight block events did not match metadata")?;
            if let Some(TxApplied(details)) = event.as_event::<TxApplied>()? {
                if details.tx_hash == *tx_hash.as_bytes() {
                    return Ok(Some(Landing::Applied));
                }
            }
            if let Some(TxPartialSuccess(details)) = event.as_event::<TxPartialSuccess>()? {
                if details.tx_hash == *tx_hash.as_bytes() {
                    return Ok(Some(Landing::PartialSuccess));
                }
            }
        }
        Ok(None)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::support::*;
    use crate::submit_error::SubmitError;
    use jsonrpsee::server::ServerBuilder;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use jsonrpsee::RpcModule;
    use mpc_chain_integration_core::utils::retry::{is_provider_throttled, is_retryable};
    use serde_json::json;

    use crate::native::SubmitChain as _;
    use crate::rpc::reads::rejected_http_status;
    use crate::rpc::transport::connect_http;
    use crate::types::NetworkId;
    use http::StatusCode;
    use subxt::backend::legacy::LegacyRpcMethods;
    use subxt::ext::codec::{Decode as _, Encode as _};
    use subxt::ext::frame_metadata::{RuntimeMetadata, RuntimeMetadataPrefixed};
    use subxt::ext::subxt_rpcs::UserError;
    use subxt::SubstrateConfig;

    #[test]
    fn a_submit_reply_is_a_refusal_only_when_the_node_answered_one() {
        let user = |code: i32, message: &str| {
            Err(RawRpcError::User(UserError {
                code,
                message: message.to_string(),
                data: Some(serde_json::value::to_raw_value("root not in arena").unwrap()),
            }))
        };
        assert!(classify_submit_reply(Ok(serde_json::json!("0x00"))).is_ok());
        assert!(
            classify_submit_reply(user(ALREADY_IMPORTED, "Transaction Already Imported")).is_ok(),
            "an already-imported transaction is in the pool"
        );
        match classify_submit_reply(user(1002, "Verification Error")) {
            Err(SubmitRefusal::Refused(reason)) => {
                assert_eq!(reason, "1002: Verification Error (\"root not in arena\")")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(matches!(
            classify_submit_reply(Err(RawRpcError::Client(Box::new(std::io::Error::other(
                "connection reset"
            ))))),
            Err(SubmitRefusal::Unanswered(_))
        ));
    }

    #[tokio::test]
    async fn a_submit_whose_runtime_cannot_be_read_is_never_sent() {
        use crate::native::SubmitChain as _;

        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let transport = connect_http(&http_config(server.local_addr().unwrap())).unwrap();
        let submits = Arc::new(AtomicUsize::new(0));
        let counted = submits.clone();
        // No chain_getBlockHash, so the node cannot name the runtime to build against.
        let mut module = RpcModule::new(());
        module
            .register_method("author_submitExtrinsic", move |_, _, _| {
                counted.fetch_add(1, Ordering::SeqCst);
                hash_of_byte(0x01)
            })
            .unwrap();
        let _handle = server.start(module);
        let rpc = MidnightPublisherRpc {
            rpc: transport.clone(),
            legacy: LegacyRpcMethods::<SubstrateConfig>::new(transport),
            genesis_hash: H256([0x11; 32]),
            clients: Default::default(),
            blocks: Default::default(),
            network_id: NetworkId::Undeployed,
        };

        match rpc.submit(&[0x00]).await {
            Err(SubmitRefusal::Unsent(_)) => {}
            other => panic!("expected an unsent submit, got {other:?}"),
        }
        assert_eq!(submits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_runtime_without_the_call_is_a_mismatch_not_an_unsent() {
        // The fixture's metadata, emptied of its pallets: the runtime reads fine,
        // but no call named send_mn_transaction exists to build.
        let raw = include_bytes!("../../fixtures/fallible-block-432-metadata.scale");
        let mut prefixed = RuntimeMetadataPrefixed::decode(&mut &raw[..]).unwrap();
        match &mut prefixed.1 {
            RuntimeMetadata::V14(v14) => v14.pallets.clear(),
            RuntimeMetadata::V15(v15) => v15.pallets.clear(),
            RuntimeMetadata::V16(v16) => v16.pallets.clear(),
            _ => panic!("the fixture is a v14–v16 metadata"),
        }
        let served = format!("0x{}", hex::encode(prefixed.encode().encode()));

        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let transport = connect_http(&http_config(server.local_addr().unwrap())).unwrap();
        let submits = Arc::new(AtomicUsize::new(0));
        let counted = submits.clone();
        let metadata = served.clone();
        let mut module = RpcModule::new(());
        module
            .register_method("chain_getBlockHash", |_, _, _| hash_of_byte(0x0b))
            .unwrap();
        module
            .register_method("state_getRuntimeVersion", |_, _, _| {
                json!({
                    "specName": "midnight",
                    "implName": "midnight",
                    "authoringVersion": 1,
                    "specVersion": 2,
                    "implVersion": 0,
                    "apis": [],
                    "transactionVersion": 2,
                    "stateVersion": 1
                })
            })
            .unwrap();
        module
            .register_method("state_call", move |params, _, _| {
                let (method, _data, _at) = params.parse::<(String, String, String)>().unwrap();
                match method.as_str() {
                    "Metadata_metadata_at_version" => "0x00".to_string(),
                    "Metadata_metadata" => metadata.clone(),
                    other => panic!("unexpected runtime call {other}"),
                }
            })
            .unwrap();
        module
            .register_method("author_submitExtrinsic", move |_, _, _| {
                counted.fetch_add(1, Ordering::SeqCst);
                hash_of_byte(0x01)
            })
            .unwrap();
        let _handle = server.start(module);
        let rpc = MidnightPublisherRpc {
            rpc: transport.clone(),
            legacy: LegacyRpcMethods::<SubstrateConfig>::new(transport),
            genesis_hash: H256([0x11; 32]),
            clients: Default::default(),
            blocks: Default::default(),
            network_id: NetworkId::Undeployed,
        };

        match rpc.submit(&[0x00]).await {
            Err(SubmitRefusal::Mismatch(_)) => {}
            other => panic!("expected a metadata mismatch, got {other:?}"),
        }
        assert_eq!(submits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn real_submit_statuses_follow_the_read_partition() {
        // The runtime read inside the submit path meets the status first, so
        // nothing is sent.
        for (status, reason, retryable, throttled) in [
            (429u16, "Too Many Requests", true, true),
            (500u16, "Internal Server Error", true, false),
            // A shared provider's transient conflict retries, like midnight's
            // other reads; a classic client error hands off to failover.
            (409u16, "Conflict", true, false),
            (404u16, "Not Found", false, false),
        ] {
            let (address, _calls, server) = http_status_server(status, reason).await;
            let config = http_config(address);
            let transport = connect_http(&config).unwrap();
            let rpc = MidnightPublisherRpc {
                rpc: transport.clone(),
                legacy: LegacyRpcMethods::<SubstrateConfig>::new(transport),
                genesis_hash: H256([0x11; 32]),
                clients: Default::default(),
                blocks: Default::default(),
                network_id: NetworkId::Undeployed,
            };

            let error = match rpc.submit(&[0x00]).await {
                Err(SubmitRefusal::Unsent(error)) => error,
                other => panic!("expected an unsent submit at {status}, got {other:?}"),
            };
            server.abort();
            let _ = server.await;
            assert_eq!(
                rejected_http_status(&error),
                Some(StatusCode::from_u16(status).unwrap()),
                "{error:#}"
            );

            let publish = SubmitError::Node {
                source: error.context("the transaction could not be sent; nothing was posted"),
            }
            .into_publish_error();
            assert_eq!(is_retryable(&publish), retryable, "{publish:#}");
            assert_eq!(is_provider_throttled(&publish), throttled, "{publish:#}");
        }
    }
}
