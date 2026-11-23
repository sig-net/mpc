//! The indexer-facing subxt client: finalized head and block reads, and the
//! block-emission extraction the indexer consumes.

use anyhow::Context as _;
use subxt::backend::legacy::rpc_methods::BlockDetails;
use subxt::client::OnlineClient;
use subxt::ext::codec::Encode as _;
use subxt::utils::H256;
use subxt::SubstrateConfig;

use super::reads::{retry_read, Reads};
use super::statics::{
    applied_status, decode_applied_transaction, AppliedStatus, SendMnTransaction, TimestampSet,
};
use super::transport::connect_http;
use crate::config::MidnightConfig;
use crate::emissions::{emissions_in, partial_success_emissions_in};
use crate::indexer::BlockHold;
use crate::source::{BlockEmissions, BlockProofSeed, CandidateTransactionEmissions};
use crate::types::{BlockHash, MidnightAddress};

/// One finalized block as plain data: the number plus the hashes of the block and
/// its parent, detached from any subxt handle so fixtures can mint them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRef {
    pub number: u64,
    pub hash: BlockHash,
    pub parent_hash: BlockHash,
}

impl From<H256> for BlockHash {
    fn from(hash: H256) -> Self {
        BlockHash::from_bytes(hash.0)
    }
}

impl From<BlockHash> for H256 {
    fn from(hash: BlockHash) -> Self {
        H256(*hash.as_bytes())
    }
}

pub struct MidnightRpc {
    client: OnlineClient<SubstrateConfig>,
    reads: Reads,
    head: std::sync::Mutex<Option<FinalizedHead>>,
    /// The block a lookup by number last read, until the indexer processes it.
    walked: std::sync::Mutex<Option<(BlockHash, BlockDetails<SubstrateConfig>)>>,
}

/// The finalized head last read, with its block until the indexer processes it.
struct FinalizedHead {
    block_ref: BlockRef,
    block: Option<BlockDetails<SubstrateConfig>>,
}

impl MidnightRpc {
    /// Builds Subxt over the request-only HTTP client named by `config.node_url`.
    pub async fn connect(config: &MidnightConfig) -> anyhow::Result<Self> {
        let rpc = connect_http(config)?;
        let client = tokio::time::timeout(
            config.rpc.connect_timeout,
            OnlineClient::<SubstrateConfig>::from_rpc_client(rpc.clone()),
        )
        .await
        .context("timed out initialising the midnight subxt client")?
        .context("failed to initialise the midnight subxt client")?;

        Ok(Self {
            client,
            reads: Reads::new(rpc, config.rpc.request_timeout, config.rpc.retry),
            head: Default::default(),
            walked: Default::default(),
        })
    }

    /// Raw contract state of `address` at `at_block_hash`, via the
    /// `midnight_contractState` JSON-RPC.
    pub async fn contract_state(
        &self,
        address: &MidnightAddress,
        at_block_hash: &BlockHash,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.reads.contract_state(address, at_block_hash).await
    }

    /// The finalized head as a [`BlockRef`]: the head hash, then, when it moved, its
    /// number and parent from [`block_or_header`](Self::block_or_header). The block is
    /// kept for [`block_emissions`](Self::block_emissions) of that head.
    pub async fn finalized_block_ref(&self) -> anyhow::Result<BlockRef> {
        let head = self.reads.finalized_head().await?;
        let hash: BlockHash = head.into();
        if let Some(known) = self.head().as_ref() {
            if known.block_ref.hash == hash {
                return Ok(known.block_ref.clone());
            }
        }
        let (number, parent_hash, block) = self
            .block_or_header(head)
            .await?
            .context("midnight node returned no header for its own finalized head")?;
        let block_ref = BlockRef {
            number,
            hash,
            parent_hash: parent_hash.into(),
        };
        *self.head() = Some(FinalizedHead {
            block_ref: block_ref.clone(),
            block,
        });
        Ok(block_ref)
    }

    /// Block `hash`'s number and parent from its block, which comes back for processing,
    /// or, when one attempt cannot read the block, from its header on the ordinary
    /// retry budget, as the block is fetched again under the per-block budget when it
    /// is processed; `None` when the node has neither.
    async fn block_or_header(
        &self,
        hash: H256,
    ) -> anyhow::Result<Option<(u64, H256, Option<BlockDetails<SubstrateConfig>>)>> {
        let error = match self.reads.block_once(hash).await {
            Ok(Some(block)) => {
                let header = &block.block.header;
                return Ok(Some((
                    u64::from(header.number),
                    header.parent_hash,
                    Some(block),
                )));
            }
            Ok(None) => "the node has no block for it".to_owned(),
            Err(error) => format!("{error:#}"),
        };
        if let Some(count) = mpc_utils::throttle::check("midnight:block-unread") {
            tracing::warn!(
                count,
                block_hash = %BlockHash::from(hash),
                error,
                "midnight: a block could not be read; reading its header"
            );
        }
        Ok(self
            .reads
            .header(hash)
            .await?
            .map(|header| (u64::from(header.number), header.parent_hash, None)))
    }

    fn head(&self) -> std::sync::MutexGuard<'_, Option<FinalizedHead>> {
        self.head
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn walked(
        &self,
    ) -> std::sync::MutexGuard<'_, Option<(BlockHash, BlockDetails<SubstrateConfig>)>> {
        self.walked
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The block at `number` as a [`BlockRef`], for the catchup range walk. The block
    /// read for it is kept for [`block_emissions`](Self::block_emissions) of that block.
    pub async fn block_ref_at(&self, number: u64) -> anyhow::Result<BlockRef> {
        let hash = self
            .reads
            .block_hash_at(number)
            .await?
            .with_context(|| format!("midnight node has no block hash for height {number}"))?;
        let (returned_number, parent_hash, block) = self
            .block_or_header(hash)
            .await?
            .with_context(|| format!("midnight node has no header for height {number}"))?;
        anyhow::ensure!(
            returned_number == number,
            "midnight block lookup requested height {number} but returned height {returned_number}"
        );
        let block_ref = BlockRef {
            number: returned_number,
            hash: hash.into(),
            parent_hash: parent_hash.into(),
        };
        *self.walked() = block.map(|block| (block_ref.hash, block));
        Ok(block_ref)
    }

    pub async fn block_emissions(
        &self,
        block_ref: &BlockRef,
        singleton: &MidnightAddress,
        responder: &MidnightAddress,
    ) -> anyhow::Result<Option<BlockEmissions>> {
        let hash = H256::from(block_ref.hash);
        let read = self
            .head()
            .as_mut()
            .filter(|head| head.block_ref.hash == block_ref.hash)
            .and_then(|head| head.block.take())
            .or_else(|| {
                self.walked()
                    .take_if(|(hash, _)| *hash == block_ref.hash)
                    .map(|(_, block)| block)
            });
        let block = match read {
            Some(block) => block,
            None => self
                .reads
                .block(hash)
                .await?
                .with_context(|| format!("midnight node has no block {}", block_ref.hash))?,
        }
        .block;
        let header = block.header;
        let extrinsics = subxt::ext::subxt_core::blocks::decode_from::<SubstrateConfig>(
            block.extrinsics.into_iter().map(|bytes| bytes.0).collect(),
            self.client.metadata(),
        )
        .map_err(anyhow::Error::new)
        .context("failed to decode a midnight block body")?;
        let height = u64::from(header.number);

        let mut candidates = Vec::new();
        for found in extrinsics.find::<SendMnTransaction>() {
            let found = found.map_err(|err| {
                BlockHold::new(
                    "emission-schema-hold",
                    height,
                    anyhow::Error::new(err).context("send_mn_transaction did not match metadata"),
                )
            })?;
            let tx = &found.value.midnight_tx;
            if memchr::memmem::find(tx, singleton.as_bytes()).is_some()
                || memchr::memmem::find(tx, responder.as_bytes()).is_some()
            {
                candidates.push(found);
            }
        }
        if candidates.is_empty() {
            return Ok(None);
        }

        // One timestamp inherent per block by substrate protocol; §4.3's
        // admission bound anchors on it, so a traffic block without a
        // decodable one holds instead of emitting without a time.
        // Arg corruption fails `decode_from` first (subxt eagerly decodes
        // call data); the decode arm is metadata drift — the payload decodes
        // per the node's metadata but not as `TimestampSet`.
        let block_time_ms = extrinsics
            .find::<TimestampSet>()
            .next()
            .transpose()
            .map_err(|err| anyhow::Error::new(err).context("timestamp set did not match metadata"))
            .and_then(|found| {
                found.ok_or_else(|| anyhow::anyhow!("block carries no timestamp inherent"))
            })
            .map_err(|cause| BlockHold::new("block-time-hold", height, cause))?
            .value
            .now;
        let block_events = retry_read(
            self.reads.request_timeout,
            self.reads.retry,
            "midnight_block_events",
            || async {
                self.client
                    .events()
                    .at(hash)
                    .await
                    .map_err(anyhow::Error::new)
                    .context("failed to fetch midnight block events")
            },
        )
        .await?;
        let mut decoded_candidates = Vec::with_capacity(candidates.len());
        for found in candidates {
            let events = subxt::blocks::ExtrinsicEvents::new(
                found.details.hash(),
                found.details.index(),
                block_events.clone(),
            );
            let applied = applied_status(&events)
                .map_err(|err| BlockHold::new("emission-schema-hold", height, err))?;
            let Some((ledger_tx_hash, status)) = applied else {
                tracing::warn!(
                    reason = "unsupported-midnight-status",
                    status = "NoTxApplied",
                    height,
                    block_hash = %block_ref.hash,
                    extrinsic_index = found.details.index(),
                    "midnight transaction skipped: it has no applied status"
                );
                continue;
            };
            let tx = decode_applied_transaction(&found.value.midnight_tx, ledger_tx_hash).map_err(
                |err| {
                    BlockHold::new(
                        "contract-tx-undecodable",
                        height,
                        err.context(format!(
                            "candidate extrinsic {} ledger transaction {ledger_tx_hash}",
                            found.details.index()
                        )),
                    )
                },
            )?;
            let decode = |contract: &MidnightAddress| {
                let schema_hold = |err: anyhow::Error| {
                    BlockHold::new(
                        "emission-schema-hold",
                        height,
                        err.context(format!(
                            "candidate extrinsic {} transaction {ledger_tx_hash} emissions of contract {contract}",
                            found.details.index()
                        )),
                    )
                };
                anyhow::Ok(match status {
                    AppliedStatus::Applied => {
                        emissions_in(&tx, contract.as_bytes()).map_err(schema_hold)?
                    }
                    AppliedStatus::PartialSuccess => {
                        let (calls, skipped) =
                            partial_success_emissions_in(&tx, contract.as_bytes())
                                .map_err(schema_hold)?;
                        for skipped in skipped {
                            tracing::warn!(
                                reason = "partial-success-fallible-skipped",
                                tx_hash = %ledger_tx_hash,
                                height,
                                block_hash = %block_ref.hash,
                                extrinsic_index = found.details.index(),
                                contract = %contract,
                                call_index = skipped.call_index,
                                physical_segment = skipped.physical_segment,
                                error = %format_args!("{:#}", skipped.reason),
                                "midnight fallible protocol contract phase skipped in a partial success"
                            );
                        }
                        calls
                    }
                })
            };
            decoded_candidates.push(CandidateTransactionEmissions {
                ledger_tx_hash,
                extrinsic_index: found.details.index(),
                partial_success: status == AppliedStatus::PartialSuccess,
                singleton_calls: decode(singleton)?,
                responder_calls: decode(responder)?,
            });
        }

        Ok(Some(BlockEmissions {
            block_time_ms,
            proof_seed: BlockProofSeed {
                reported_genesis_hash: *self.client.genesis_hash().as_fixed_bytes(),
                reported_block_number: height,
                reported_block_hash: *hash.as_fixed_bytes(),
                singleton_address: *singleton.as_bytes(),
                responder_address: *responder.as_bytes(),
                scale_header: header.encode(),
                scale_body: extrinsics
                    .iter()
                    .map(|extrinsic| extrinsic.bytes().to_vec())
                    .collect(),
                scale_system_events: block_events.bytes().to_vec(),
            },
            candidates: decoded_candidates,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::support::*;
    use jsonrpsee::server::ServerBuilder;
    use jsonrpsee::types::ErrorObjectOwned;
    use jsonrpsee::RpcModule;
    use serde_json::json;
    use std::io::Write as _;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use subxt::ext::codec::DecodeAll as _;

    use crate::config::RpcConfig;
    use crate::emissions::DecodedTransaction;
    use crate::rpc::statics::TxApplied;
    use crate::types::LedgerTxHash;

    async fn read_fallible_capture(events: Vec<u8>) -> anyhow::Result<Option<BlockEmissions>> {
        read_fallible_transaction(
            events,
            include_bytes!("../../fixtures/fallible-deposit-tx-432.mn"),
            FixtureTimestamp::Set,
        )
        .await
    }

    /// The vault capture's singleton.
    const CAPTURE_SINGLETON: &str =
        "4daa9701226222a9db302dfb6f347f48c947278a4dc93812a79494f4086a0172";
    /// A responder no captured transaction calls.
    const ABSENT_RESPONDER: [u8; 32] = [0xcd; 32];

    async fn read_fallible_transaction(
        events: Vec<u8>,
        transaction: &[u8],
        timestamp: FixtureTimestamp,
    ) -> anyhow::Result<Option<BlockEmissions>> {
        read_fallible_transaction_as(
            events,
            transaction,
            crate::test_utils::hex_32(CAPTURE_SINGLETON),
            ABSENT_RESPONDER,
            timestamp,
        )
        .await
    }

    async fn read_fallible_transaction_as(
        events: Vec<u8>,
        transaction: &[u8],
        singleton: [u8; 32],
        responder: [u8; 32],
        timestamp: FixtureTimestamp,
    ) -> anyhow::Result<Option<BlockEmissions>> {
        let metadata = subxt::Metadata::decode_all(
            &mut &include_bytes!("../../fixtures/fallible-block-432-metadata.scale")[..],
        )?;
        let server = ServerBuilder::default().build("127.0.0.1:0").await?;
        let mut config = http_config(server.local_addr()?);
        config.rpc.retry = attempts(0);
        let transport = connect_http(&config)?;
        // The header and extrinsic wrappers are synthetic, encoded against captured
        // metadata. Most cases use unchanged captured transaction/status bytes;
        // variants explicitly alter them. This is not an inclusion proof.
        let client = OnlineClient::<SubstrateConfig>::from_rpc_client_with(
            H256([0x11; 32]),
            subxt::client::RuntimeVersion {
                spec_version: 1,
                transaction_version: 1,
            },
            metadata,
            transport.clone(),
        )?;
        let filler = client.tx().create_unsigned(&subxt::dynamic::tx(
            "System",
            "remark",
            vec![subxt::dynamic::Value::from_bytes([])],
        ))?;
        let candidate = client.tx().create_unsigned(&subxt::dynamic::tx(
            "Midnight",
            "send_mn_transaction",
            vec![subxt::dynamic::Value::from_bytes(transaction)],
        ))?;
        // Preserve the captured candidate's extrinsic index, including preceding
        // unrelated calls, so status association is exercised by Subxt itself.
        let mut body = vec![format!("0x{}", hex::encode(filler.encoded())); 4];
        body.push(format!("0x{}", hex::encode(candidate.encoded())));
        let set_call = client.tx().create_unsigned(&subxt::dynamic::tx(
            "Timestamp",
            "set",
            vec![subxt::dynamic::Value::from(FIXTURE_BLOCK_TIME_MS)],
        ))?;
        match timestamp {
            FixtureTimestamp::Set => {
                body.push(format!("0x{}", hex::encode(set_call.encoded())));
            }
            FixtureTimestamp::Corrupted => {
                let encoded = set_call.encoded();
                let (prefix, payload) = encoded.split_first().expect("encoded extrinsic");
                assert!(payload.len() < 62, "single-byte compact prefix");
                let mut corrupted = vec![prefix + 4];
                corrupted.extend_from_slice(payload);
                corrupted.push(0x00);
                body.push(format!("0x{}", hex::encode(corrupted)));
            }
            FixtureTimestamp::Absent => {}
        }
        let header = json!({
            "parentHash": hash_of_byte(0x42),
            "number": "0x1b0",
            "stateRoot": hash_of_byte(0x44),
            "extrinsicsRoot": hash_of_byte(0x45),
            "digest": { "logs": [] }
        });
        // No chain_getHeader: the block read takes the header from chain_getBlock.
        let mut module = RpcModule::new(());
        module.register_method("chain_getBlock", move |params, _, _| {
            assert_eq!(params.parse::<Vec<String>>().unwrap(), [hash_of_byte(0x43)]);
            json!({ "block": { "header": header, "extrinsics": body }, "justifications": null })
        })?;
        let events_key = client.storage().address_bytes(&subxt::dynamic::storage(
            "System",
            "Events",
            Vec::<subxt::dynamic::Value>::new(),
        ))?;
        module.register_method("state_getStorage", move |params, _, _| {
            assert_eq!(
                params.parse::<Vec<String>>().unwrap(),
                [
                    format!("0x{}", hex::encode(&events_key)),
                    hash_of_byte(0x43)
                ]
            );
            format!("0x{}", hex::encode(&events))
        })?;
        let handle = server.start(module);
        let rpc = MidnightRpc {
            client,
            reads: Reads::new(transport, config.rpc.request_timeout, config.rpc.retry),
            head: Default::default(),
            walked: Default::default(),
        };
        let block = BlockRef {
            number: 432,
            hash: BlockHash::from_bytes([0x43; 32]),
            parent_hash: BlockHash::from_bytes([0x42; 32]),
        };
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            rpc.block_emissions(
                &block,
                &MidnightAddress::from_bytes(singleton),
                &MidnightAddress::from_bytes(responder),
            ),
        )
        .await;
        handle.stop()?;
        handle.stopped().await;
        result.context("block reader timed out")?
    }

    #[tokio::test]
    async fn block_reader_extracts_captured_applied_fallible_notification() {
        let events = include_bytes!("../../fixtures/fallible-block-432-events.scale").to_vec();
        let block = read_fallible_capture(events.clone())
            .await
            .expect("read captured fallible transaction")
            .expect("block contains a singleton candidate");
        assert_eq!(block.proof_seed.reported_block_number, 432);
        assert_eq!(block.proof_seed.reported_block_hash, [0x43; 32]);
        assert_eq!(block.proof_seed.scale_body.len(), 6);
        assert_eq!(block.proof_seed.scale_system_events, events);
        assert_eq!(block.block_time_ms, FIXTURE_BLOCK_TIME_MS);
        assert_eq!(block.candidates.len(), 1);
        let candidate = &block.candidates[0];
        assert_eq!(candidate.extrinsic_index, 4);
        assert_eq!(
            candidate.ledger_tx_hash,
            LedgerTxHash::from_bytes(crate::test_utils::hex_32(
                "ba41ac43f2cfa97e32357877b85210a7f2105f4930b60515e19aa9ec00bb0f5d"
            ))
        );
        assert_eq!(candidate.singleton_calls.len(), 1);
        assert!(candidate.responder_calls.is_empty());
        let call = &candidate.singleton_calls[0];
        assert_eq!(call.call_index, 1);
        assert_eq!(call.physical_segment, 49592);
        assert_eq!(call.phase, crate::emissions::TranscriptPhase::Fallible);
        assert_eq!(call.emissions.len(), 1);
        assert_eq!(
            call.emissions[0].kind,
            crate::emissions::EmissionKind::SignBidirectional
        );
        assert_eq!(
            call.emissions[0].payload[1..33],
            crate::test_utils::hex_32(
                "ee3385dda706877d30e802a0df57c228310016889104b8fb361c830a58d1e500"
            )
        );
    }

    #[tokio::test]
    async fn block_reader_finds_calls_by_the_responder_address_too() {
        // The decoder keys on the address alone, so the captured call stands in for a
        // responder call when the responder is configured at its address.
        let block = read_fallible_transaction_as(
            include_bytes!("../../fixtures/fallible-block-432-events.scale").to_vec(),
            include_bytes!("../../fixtures/fallible-deposit-tx-432.mn"),
            [0xab; 32],
            crate::test_utils::hex_32(CAPTURE_SINGLETON),
            FixtureTimestamp::Set,
        )
        .await
        .expect("read captured fallible transaction")
        .expect("block contains a responder candidate");
        assert_eq!(
            block.proof_seed.responder_address,
            crate::test_utils::hex_32(CAPTURE_SINGLETON)
        );
        let [candidate] = block.candidates.as_slice() else {
            panic!("expected one candidate: {:?}", block.candidates);
        };
        assert!(candidate.singleton_calls.is_empty());
        let [call] = candidate.responder_calls.as_slice() else {
            panic!(
                "expected one responder call: {:?}",
                candidate.responder_calls
            );
        };
        assert_eq!((call.call_index, call.physical_segment), (1, 49592));
    }

    #[tokio::test]
    async fn a_traffic_block_without_a_timestamp_inherent_holds() {
        let events = include_bytes!("../../fixtures/fallible-block-432-events.scale").to_vec();
        let transaction = include_bytes!("../../fixtures/fallible-deposit-tx-432.mn");
        let err = read_fallible_transaction(events, transaction, FixtureTimestamp::Absent)
            .await
            .expect_err("a traffic block must carry its timestamp inherent");
        let hold = err.downcast_ref::<BlockHold>().expect("typed block hold");
        assert_eq!(hold.reason, "block-time-hold");
        assert_eq!(hold.height, 432);
        assert!(
            format!("{:#}", hold.cause).contains("block carries no timestamp inherent"),
            "unexpected cause: {:#}",
            hold.cause
        );
    }

    #[tokio::test]
    async fn corrupted_timestamp_arguments_fail_the_body_fetch() {
        // subxt eagerly decodes call data at the body fetch, so arg
        // corruption never reaches the reader — the fetch fails and the
        // supervised run restarts.
        let events = include_bytes!("../../fixtures/fallible-block-432-events.scale").to_vec();
        let transaction = include_bytes!("../../fixtures/fallible-deposit-tx-432.mn");
        let err = read_fallible_transaction(events, transaction, FixtureTimestamp::Corrupted)
            .await
            .expect_err("a traffic block must carry a decodable timestamp");
        assert!(
            err.downcast_ref::<BlockHold>().is_none(),
            "arg corruption is a fetch failure, not a hold: {err:#}"
        );
        assert!(format!("{err:#}").contains("failed to decode a midnight block body"));
        assert!(format!("{err:#}").contains("bytes were left"));
    }

    #[tokio::test]
    async fn block_reader_extracts_fallible_notification_with_zero_noop() {
        use midnight_ledger_v9::structure::ContractAction;
        use midnight_onchain_runtime::{
            context::QueryContext,
            cost_model::INITIAL_COST_MODEL,
            ops::Op,
            result_mode::ResultModeVerify,
            state::{ChargedState, StateValue},
        };
        use midnight_storage::{arena::Sp, storage::Array};

        let bytes = include_bytes!("../../fixtures/fallible-deposit-tx-432.mn");
        let tx: DecodedTransaction =
            midnight_serialize::tagged_deserialize(&mut &bytes[..]).unwrap();
        let (segment, original) = tx.calls().nth(1).unwrap();
        let context = QueryContext::new(
            ChargedState::new(StateValue::Array(Array::new())),
            original.address,
        );
        let mut transcript = original.fallible_transcript.as_deref().unwrap().clone();
        // Unbounded: the capture's declared deletions exceed what ledger 9.1.0.1 prices for
        // its writes, and 9.1.0.1 refuses `noop 0` as not normalized, so neither declared gas
        // bound applies to this fixture any longer.
        let before = context
            .query::<ResultModeVerify>(&Vec::from(&transcript.program), None, &INITIAL_COST_MODEL)
            .unwrap();
        let mut program = Vec::from(&transcript.program);
        program.push(Op::Noop { n: 0 });
        transcript.program = program.into();
        let after = context
            .query::<ResultModeVerify>(&Vec::from(&transcript.program), None, &INITIAL_COST_MODEL)
            .expect("zero noop executes");
        assert_eq!(before.events, after.events);
        assert_eq!(before.context.effects, after.context.effects);

        let DecodedTransaction::Standard(mut tx) = tx else {
            panic!("standard captured transaction");
        };
        let mut intent = (*tx.intents.get(&segment).unwrap()).clone();
        let mut modified = original.clone();
        modified.fallible_transcript = Some(Sp::new(transcript));
        let binding = intent.binding_commitment.clone().into();
        assert_eq!(
            original.public_inputs(binding).unwrap(),
            modified.public_inputs(binding).unwrap(),
            "fallible Noop(0) leaves the existing contract proof inputs unchanged"
        );
        let mut actions = Vec::from(&intent.actions);
        let action = actions
            .iter_mut()
            .find(|action| matches!(action, ContractAction::Call(call) if call.address == original.address))
            .unwrap();
        *action = ContractAction::Call(Sp::new(modified));
        intent.actions = actions.into();
        tx.intents = tx.intents.insert(segment, intent);
        let tx = DecodedTransaction::Standard(tx);
        let mut bytes = Vec::new();
        midnight_serialize::tagged_serialize(&tx, &mut bytes).unwrap();
        let hash = tx.transaction_hash().0 .0;
        let mut applied = captured_applied_status_record();
        assert_eq!(&applied[..7], &[0, 4, 0, 0, 0, 5, 2]);
        applied[7..39].copy_from_slice(&hash);

        // This reader fixture does not reseal the outer intent or pay changed fees.
        // Its matching status is synthetic; the assertions above establish the
        // contract-proof inputs and VM behavior, not acceptance by a live node.
        let block = read_fallible_transaction(
            encode_status_records(&[applied]),
            &bytes,
            FixtureTimestamp::Set,
        )
        .await
        .expect("a harmless noop must not hold block processing")
        .unwrap();
        assert_eq!(block.candidates.len(), 1);
        assert_eq!(
            block.candidates[0].ledger_tx_hash,
            LedgerTxHash::from_bytes(hash)
        );
        let calls = &block.candidates[0].singleton_calls;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].call_index, 1);
        assert_eq!(calls[0].physical_segment, segment);
        assert_eq!(calls[0].phase, crate::emissions::TranscriptPhase::Fallible);
        assert_eq!(calls[0].emissions.len(), 1);
        assert_eq!(
            calls[0].emissions[0].kind,
            crate::emissions::EmissionKind::SignBidirectional
        );
        assert_eq!(
            calls[0].emissions[0].payload[1..33],
            crate::test_utils::hex_32(
                "ee3385dda706877d30e802a0df57c228310016889104b8fb361c830a58d1e500"
            )
        );
    }

    #[tokio::test]
    async fn block_reader_extracts_fallible_notification_with_checkpoints() {
        use midnight_ledger_v9::structure::ContractAction;
        use midnight_onchain_runtime::ops::Op;
        use midnight_storage::arena::Sp;

        let bytes = include_bytes!("../../fixtures/fallible-deposit-tx-432.mn");
        let tx: DecodedTransaction =
            midnight_serialize::tagged_deserialize(&mut &bytes[..]).unwrap();
        let (segment, mut call) = tx.calls().nth(1).unwrap();
        let singleton = call.address.0 .0;
        let expected = emissions_in(&tx, &singleton).unwrap();
        let mut transcript = call.fallible_transcript.as_deref().unwrap().clone();
        let original = Vec::from(&transcript.program);
        assert!(matches!(
            original.as_slice(),
            [Op::Push { storage: false, .. }, Op::Log]
        ));
        transcript.program = vec![
            Op::Ckpt,
            original[0].clone(),
            Op::Ckpt,
            Op::Noop { n: 0 },
            Op::Ckpt,
            original[1].clone(),
            Op::Ckpt,
        ]
        .into();
        call.fallible_transcript = Some(Sp::new(transcript));
        let DecodedTransaction::Standard(mut tx) = tx else {
            panic!("standard captured transaction");
        };
        let mut intent = (*tx.intents.get(&segment).unwrap()).clone();
        let mut actions = Vec::from(&intent.actions);
        let action = actions
            .iter_mut()
            .find(|action| matches!(action, ContractAction::Call(call) if call.address.0 .0 == singleton))
            .unwrap();
        *action = ContractAction::Call(Sp::new(call));
        intent.actions = actions.into();
        tx.intents = tx.intents.insert(segment, intent);
        let tx = DecodedTransaction::Standard(tx);
        let mut bytes = Vec::new();
        midnight_serialize::tagged_serialize(&tx, &mut bytes).unwrap();
        let hash = tx.transaction_hash().0 .0;
        let mut applied = captured_applied_status_record();
        applied[7..39].copy_from_slice(&hash);

        // Modified program and matching status are synthetic. This exercises the
        // production reader, not proof validity, gas admission or node acceptance.
        let block = read_fallible_transaction(
            encode_status_records(&[applied]),
            &bytes,
            FixtureTimestamp::Set,
        )
        .await
        .expect("checkpoints must not hide the captured event")
        .unwrap();
        assert_eq!(block.candidates.len(), 1);
        assert_eq!(
            block.candidates[0].ledger_tx_hash,
            LedgerTxHash::from_bytes(hash)
        );
        assert_eq!(block.candidates[0].singleton_calls, expected);
    }

    /// The captured fallible deposit with its singleton call's fallible transcript edited,
    /// re-encoded with matching `TxApplied` and `TxPartialSuccess` status records.
    fn edited_fallible_deposit(
        edit: impl FnOnce(
            &mut midnight_onchain_runtime::transcript::Transcript<midnight_storage::DefaultDB>,
        ),
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use midnight_ledger_v9::structure::ContractAction;
        use midnight_storage::arena::Sp;

        let bytes = include_bytes!("../../fixtures/fallible-deposit-tx-432.mn");
        let tx: DecodedTransaction =
            midnight_serialize::tagged_deserialize(&mut &bytes[..]).unwrap();
        let (segment, mut call) = tx.calls().nth(1).unwrap();
        let singleton = call.address.0 .0;
        let mut transcript = call.fallible_transcript.as_deref().unwrap().clone();
        edit(&mut transcript);
        call.fallible_transcript = Some(Sp::new(transcript));
        let DecodedTransaction::Standard(mut tx) = tx else {
            panic!("standard captured transaction");
        };
        let mut intent = (*tx.intents.get(&segment).unwrap()).clone();
        let mut actions = Vec::from(&intent.actions);
        let action = actions
            .iter_mut()
            .find(|action| matches!(action, ContractAction::Call(call) if call.address.0 .0 == singleton))
            .unwrap();
        *action = ContractAction::Call(Sp::new(call));
        intent.actions = actions.into();
        tx.intents = tx.intents.insert(segment, intent);
        let tx = DecodedTransaction::Standard(tx);
        let mut bytes = Vec::new();
        midnight_serialize::tagged_serialize(&tx, &mut bytes).unwrap();
        let mut applied = captured_applied_status_record();
        applied[7..39].copy_from_slice(&tx.transaction_hash().0 .0);
        let mut partial = applied.clone();
        partial[6] = 7; // TxPartialSuccess in the captured metadata.
        (bytes, applied, partial)
    }

    #[tokio::test]
    async fn block_reader_skips_a_fallible_effects_mismatch_only_in_a_partial_success() {
        let (bytes, applied, partial) = edited_fallible_deposit(|transcript| {
            transcript.effects.unshielded_mints =
                midnight_storage::storage::HashMap::new().insert(Default::default(), 1);
        });

        // Synthetic effects and statuses: this exercises the reader's status policy, not
        // node acceptance of such a transaction.
        let recorder = crate::test_utils::EventRecorder::default();
        // Keep a second scoped dispatch registered so callsites first reached by a
        // parallel test register against the live dispatches, not that thread's default.
        let _registration_guard = tracing::subscriber::set_default(tracing_subscriber::registry());
        let subscriber = tracing_subscriber::layer::SubscriberExt::with(
            tracing_subscriber::registry(),
            recorder.clone(),
        );
        let subscriber_guard = tracing::subscriber::set_default(subscriber);
        let block = read_fallible_transaction(
            encode_status_records(&[partial]),
            &bytes,
            FixtureTimestamp::Set,
        )
        .await
        .expect("a fallible effects mismatch in a partial success does not hold")
        .unwrap();
        drop(subscriber_guard);
        assert_eq!(block.candidates.len(), 1);
        assert!(block.candidates[0].singleton_calls.is_empty());
        let skipped = recorder
            .snapshot()
            .into_iter()
            .filter(|fields| {
                fields.get("reason").map(String::as_str)
                    == Some("\"partial-success-fallible-skipped\"")
            })
            .collect::<Vec<_>>();
        let [skipped] = skipped.as_slice() else {
            panic!("expected one skipped-phase warning, got {skipped:?}");
        };
        assert_eq!(skipped.get("call_index").map(String::as_str), Some("1"));
        assert!(skipped["error"].contains("declared effects differ"));

        let err = read_fallible_transaction(
            encode_status_records(&[applied]),
            &bytes,
            FixtureTimestamp::Set,
        )
        .await
        .expect_err("the same phase of a fully applied transaction holds");
        let hold = err.downcast_ref::<BlockHold>().expect("typed block hold");
        assert_eq!(hold.reason, "emission-schema-hold");
    }

    #[tokio::test]
    async fn block_reader_holds_any_other_undecodable_fallible_phase_in_a_partial_success() {
        let (bytes, applied, partial) = edited_fallible_deposit(|transcript| {
            let mut program = Vec::from(&transcript.program);
            program.push(midnight_onchain_runtime::ops::Op::Pop);
            transcript.program = program.into();
        });

        for status in [partial, applied] {
            let err = read_fallible_transaction(
                encode_status_records(&[status]),
                &bytes,
                FixtureTimestamp::Set,
            )
            .await
            .expect_err("an unsupported fallible program holds");
            let hold = err.downcast_ref::<BlockHold>().expect("typed block hold");
            assert_eq!(hold.reason, "emission-schema-hold");
        }
    }

    #[tokio::test]
    async fn block_reader_reads_partial_success_and_skips_other_extrinsics_statuses() {
        let applied = captured_applied_status_record();
        assert_eq!(&applied[..7], &[0, 4, 0, 0, 0, 5, 2]);
        let fully_applied =
            read_fallible_capture(encode_status_records(std::slice::from_ref(&applied)))
                .await
                .unwrap()
                .unwrap();
        let mut partial = applied.clone();
        partial[6] = 7; // TxPartialSuccess in the captured metadata.
        let mut other_extrinsic = applied;
        other_extrinsic[1..5].copy_from_slice(&0u32.to_le_bytes());
        for records in [
            vec![partial.clone()],
            vec![other_extrinsic.clone(), partial],
        ] {
            let block = read_fallible_capture(encode_status_records(&records))
                .await
                .expect("a partial success is read")
                .expect("candidate is present in the block body");
            // The capture's only singleton phase is a fallible notification, which a
            // partial success keeps.
            let mut expected = fully_applied.candidates.clone();
            assert!(!expected[0].partial_success);
            expected[0].partial_success = true;
            assert_eq!(block.candidates, expected);
        }
        let block = read_fallible_capture(encode_status_records(&[other_extrinsic]))
            .await
            .expect("an unapplied candidate is skipped")
            .expect("candidate is present in the block body");
        assert!(block.candidates.is_empty());
    }

    #[tokio::test]
    async fn block_reader_holds_when_applied_hash_does_not_match_transaction() {
        let mut applied = captured_applied_status_record();
        assert_eq!(&applied[..7], &[0, 4, 0, 0, 0, 5, 2]);
        applied[7] ^= 1; // First byte of TxAppliedDetails.tx_hash.
        let err = read_fallible_capture(encode_status_records(&[applied]))
            .await
            .expect_err("a different transaction's status must hold the block");
        let hold = err.downcast_ref::<BlockHold>().expect("typed block hold");
        assert_eq!(hold.height, 432);
        assert_eq!(hold.reason, "contract-tx-undecodable");
        assert!(format!("{:#}", hold.cause).contains("hash does not match"));
    }

    fn capture_output_dir(value: &str) -> anyhow::Result<PathBuf> {
        anyhow::ensure!(
            !value.is_empty(),
            "MIDNIGHT_CAPTURE_OUT_DIR must not be empty"
        );
        Ok(PathBuf::from(value))
    }

    fn write_new_capture(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?
            .write_all(bytes)
    }

    fn fresh_capture_test_dir() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "mpc-chain-midnight-capture-path-test-{}",
            std::process::id()
        ));
        for suffix in 0..1024 {
            let candidate = base.with_extension(suffix.to_string());
            match std::fs::create_dir(&candidate) {
                Ok(()) => return candidate,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("create capture path test directory: {err}"),
            }
        }
        panic!("could not allocate a capture path test directory");
    }

    #[test]
    fn capture_path_rejects_an_empty_output_directory() {
        let err = capture_output_dir("").expect_err("an empty output path must be rejected");

        assert!(
            err.to_string().contains("must not be empty"),
            "unexpected empty-path error: {err:#}"
        );
    }

    #[test]
    fn capture_path_refuses_an_existing_target_without_changing_it() {
        let output_dir = fresh_capture_test_dir();
        let target = output_dir.join("tx-42-7.mn");
        let original = b"existing capture that must survive";
        std::fs::write(&target, original).expect("seed existing capture");

        let err = write_new_capture(&target, b"replacement")
            .expect_err("an existing capture target must be refused");

        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&target).expect("read preserved capture"),
            original
        );
        std::fs::remove_file(&target).expect("remove capture path test file");
        std::fs::remove_dir(&output_dir).expect("remove capture path test directory");
    }

    #[tokio::test]
    #[ignore = "capture tool: MIDNIGHT_NODE_URL, MIDNIGHT_CAPTURE_BLOCK, MIDNIGHT_CAPTURE_SINGLETON, MIDNIGHT_CAPTURE_OUT_DIR"]
    async fn capture_block_fixtures() {
        let node_url = std::env::var("MIDNIGHT_NODE_URL")
            .expect("MIDNIGHT_NODE_URL must name the capture node HTTP endpoint")
            .parse()
            .expect("MIDNIGHT_NODE_URL must be a URL");
        let height = std::env::var("MIDNIGHT_CAPTURE_BLOCK")
            .expect("MIDNIGHT_CAPTURE_BLOCK must name one capture height")
            .parse::<u64>()
            .expect("MIDNIGHT_CAPTURE_BLOCK must be a u64");
        let singleton_hex = std::env::var("MIDNIGHT_CAPTURE_SINGLETON")
            .expect("MIDNIGHT_CAPTURE_SINGLETON must be 32 bytes of hex")
            .trim_start_matches("0x")
            .to_ascii_lowercase();
        let singleton: [u8; 32] = hex::decode(&singleton_hex)
            .expect("MIDNIGHT_CAPTURE_SINGLETON must be hex")
            .try_into()
            .expect("MIDNIGHT_CAPTURE_SINGLETON must be exactly 32 bytes");
        let output_dir = capture_output_dir(
            &std::env::var("MIDNIGHT_CAPTURE_OUT_DIR")
                .expect("MIDNIGHT_CAPTURE_OUT_DIR must name the fixture output directory"),
        )
        .expect("MIDNIGHT_CAPTURE_OUT_DIR must name a non-empty fixture output directory");
        std::fs::create_dir_all(&output_dir).expect("create capture output directory");

        let config = crate::config::MidnightConfig {
            node_url,
            central_address: MidnightAddress::from_bytes(singleton),
            // Unread: the capture reads only the singleton's calls.
            responder_address: MidnightAddress::from_bytes([0; 32]),
            publisher: Default::default(),
            rpc: Default::default(),
            indexer: Default::default(),
        };
        let rpc = MidnightRpc::connect(&config)
            .await
            .expect("connect to capture node");
        let block_ref = rpc
            .block_ref_at(height)
            .await
            .expect("resolve capture block");
        let block_hash = H256::from(block_ref.hash);
        let block = rpc
            .client
            .blocks()
            .at(block_hash)
            .await
            .expect("read capture block");
        let extrinsics = block.extrinsics().await.expect("read capture block body");

        let mut captured = 0usize;
        for found in extrinsics.find::<SendMnTransaction>() {
            let found = found.expect("decode send_mn_transaction from live metadata");
            if !found
                .value
                .midnight_tx
                .windows(singleton.len())
                .any(|window| window == singleton)
            {
                continue;
            }

            let extrinsic_index = found.details.index();
            let path = output_dir.join(format!("tx-{height}-{extrinsic_index}.mn"));
            let events = found.details.events().await.expect("read extrinsic events");
            let applied = events
                .find_first::<TxApplied>()
                .expect("decode TxApplied from live metadata");
            let TxApplied(details) =
                applied.expect("capture candidate must have a supported TxApplied status");
            let status = "TxApplied";
            let status_hash = details.tx_hash;
            let contract_calls = events
                .find::<CaptureContractCall>()
                .map(|call| {
                    let CaptureContractCall(details) =
                        call.expect("decode ContractCall from live metadata");
                    assert_eq!(
                        details.tx_hash, status_hash,
                        "ContractCall and status must name the same ledger transaction"
                    );
                    format!("0x{}", hex::encode(details.contract_address))
                })
                .collect::<Vec<_>>();
            write_new_capture(&path, &found.value.midnight_tx)
                .expect("create new transaction fixture without replacing an existing capture");

            println!(
                "capture block={height} hash={} extrinsic_index={extrinsic_index} \
                 status={status} tx_hash=0x{} contract_calls={contract_calls:?} file={}",
                block_ref.hash,
                hex::encode(status_hash),
                path.display()
            );
            captured += 1;
        }
        assert!(
            captured > 0,
            "capture block contains no singleton candidate"
        );

        if let Ok(caller_hex) = std::env::var("MIDNIGHT_CAPTURE_CALLER") {
            let caller_hex = caller_hex.trim_start_matches("0x").to_ascii_lowercase();
            let caller: [u8; 32] = hex::decode(&caller_hex)
                .expect("MIDNIGHT_CAPTURE_CALLER must be hex")
                .try_into()
                .expect("MIDNIGHT_CAPTURE_CALLER must be exactly 32 bytes");
            let caller_state = rpc
                .contract_state(&MidnightAddress::from_bytes(caller), &block_ref.hash)
                .await
                .expect("read caller state at capture block")
                .expect("caller contract must exist at capture block");
            let caller_path = output_dir.join(format!("caller-post-state-{height}.mn"));

            write_new_capture(&caller_path, &caller_state)
                .expect("create new caller state fixture without replacing an existing capture");

            println!(
                "capture block={height} caller_state={}",
                caller_path.display()
            );
        }
    }

    /// header and block read with its hash.
    /// An indexer node whose finalized head is `[0x43; 32]` at 0x1b0, each block `[b; 32]`
    /// numbered from it, answering `chain_getBlock` with `block`; the log names each
    /// header and block read with its hash.
    async fn numbered_indexer_node(
        block: fn(serde_json::Value) -> serde_json::Value,
    ) -> (
        MidnightRpc,
        jsonrpsee::server::ServerHandle,
        Arc<std::sync::Mutex<Vec<(&'static str, String)>>>,
    ) {
        fn header(hash: &str) -> serde_json::Value {
            let byte = u8::from_str_radix(&hash[2..4], 16).unwrap();
            json!({
                "parentHash": hash_of_byte(byte - 1),
                "number": format!("0x{:x}", 0x1b0 + u32::from(byte) - 0x43),
                "stateRoot": hash_of_byte(0x44),
                "extrinsicsRoot": hash_of_byte(0x45),
                "digest": { "logs": [] }
            })
        }
        let metadata = subxt::Metadata::decode_all(
            &mut &include_bytes!("../../fixtures/fallible-block-432-metadata.scale")[..],
        )
        .unwrap();
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let mut config = http_config(server.local_addr().unwrap());
        config.rpc.retry = attempts(0);
        let transport = connect_http(&config).unwrap();
        let client = OnlineClient::<SubstrateConfig>::from_rpc_client_with(
            H256([0x11; 32]),
            subxt::client::RuntimeVersion {
                spec_version: 1,
                transaction_version: 1,
            },
            metadata,
            transport.clone(),
        )
        .unwrap();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut module = RpcModule::new(());
        module
            .register_method("chain_getFinalizedHead", |_, _, _| hash_of_byte(0x43))
            .unwrap();
        module
            .register_method("chain_getBlockHash", |params, _, _| {
                let [number] = params.parse::<[u64; 1]>().unwrap();
                hash_of_byte((number + 0x43 - 0x1b0) as u8)
            })
            .unwrap();
        let logged = log.clone();
        module
            .register_method("chain_getBlock", move |params, _, _| {
                let [hash] = params.parse::<[String; 1]>().unwrap();
                logged
                    .lock()
                    .unwrap()
                    .push(("chain_getBlock", hash.clone()));
                block(json!({
                    "block": { "header": header(&hash), "extrinsics": [] },
                    "justifications": null
                }))
            })
            .unwrap();
        let logged = log.clone();
        module
            .register_method("chain_getHeader", move |params, _, _| {
                let [hash] = params.parse::<[String; 1]>().unwrap();
                logged
                    .lock()
                    .unwrap()
                    .push(("chain_getHeader", hash.clone()));
                header(&hash)
            })
            .unwrap();
        let handle = server.start(module);
        let rpc = MidnightRpc {
            client,
            reads: Reads::new(transport, config.rpc.request_timeout, config.rpc.retry),
            head: Default::default(),
            walked: Default::default(),
        };
        (rpc, handle, log)
    }

    #[tokio::test]
    async fn the_kept_head_block_serves_that_head_alone() {
        let (rpc, _handle, log) = numbered_indexer_node(|block| block).await;
        assert_eq!(
            rpc.finalized_block_ref().await.unwrap(),
            numbered_block_ref(0x43)
        );
        rpc.block_emissions(&numbered_block_ref(0x42), &addr(0xab), &addr(0xcd))
            .await
            .unwrap();
        rpc.block_emissions(&numbered_block_ref(0x43), &addr(0xab), &addr(0xcd))
            .await
            .unwrap();
        assert_eq!(
            *log.lock().unwrap(),
            [
                ("chain_getBlock", hash_of_byte(0x43)),
                ("chain_getBlock", hash_of_byte(0x42))
            ]
        );
    }

    /// A block read that fails is tried once before the header is read, whatever the
    /// retry budget: the poll goes on as soon as the header answers.
    #[tokio::test]
    async fn a_failed_block_read_falls_back_to_the_header_at_once() {
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let config = http_config(server.local_addr().unwrap());
        let blocks = Arc::new(AtomicUsize::new(0));
        let mut module = RpcModule::new(());
        module
            .register_method("chain_getFinalizedHead", |_, _, _| hash_of_byte(0x43))
            .unwrap();
        let read = blocks.clone();
        module
            .register_method("chain_getBlock", move |_, _, _| {
                read.fetch_add(1, Ordering::SeqCst);
                Err::<serde_json::Value, _>(ErrorObjectOwned::owned(
                    -32000,
                    "the backend is behind",
                    None::<()>,
                ))
            })
            .unwrap();
        module
            .register_method("chain_getHeader", |_, _, _| {
                json!({
                    "parentHash": hash_of_byte(0x42),
                    "number": "0x1b0",
                    "stateRoot": hash_of_byte(0x44),
                    "extrinsicsRoot": hash_of_byte(0x45),
                    "digest": { "logs": [] }
                })
            })
            .unwrap();
        let _handle = server.start(module);
        let metadata = subxt::Metadata::decode_all(
            &mut &include_bytes!("../../fixtures/fallible-block-432-metadata.scale")[..],
        )
        .unwrap();
        let transport = connect_http(&config).unwrap();
        let rpc = MidnightRpc {
            client: OnlineClient::<SubstrateConfig>::from_rpc_client_with(
                H256([0x11; 32]),
                subxt::client::RuntimeVersion {
                    spec_version: 1,
                    transaction_version: 1,
                },
                metadata,
                transport.clone(),
            )
            .unwrap(),
            reads: Reads::new(
                transport,
                Duration::from_secs(5),
                RpcConfig::default().retry,
            ),
            head: Default::default(),
            walked: Default::default(),
        };

        assert_eq!(rpc.finalized_block_ref().await.unwrap().number, 0x1b0);
        assert_eq!(blocks.load(Ordering::SeqCst), 1);
    }

    /// A block looked up by number is read once: its number and parent come from the
    /// block, which its processing then takes. It serves that block alone.
    #[tokio::test]
    async fn a_block_looked_up_by_number_is_read_once() {
        let (rpc, _handle, log) = numbered_indexer_node(|block| block).await;
        assert_eq!(
            rpc.block_ref_at(0x1af).await.unwrap(),
            numbered_block_ref(0x42)
        );
        rpc.block_emissions(&numbered_block_ref(0x41), &addr(0xab), &addr(0xcd))
            .await
            .unwrap();
        rpc.block_emissions(&numbered_block_ref(0x42), &addr(0xab), &addr(0xcd))
            .await
            .unwrap();
        assert_eq!(
            *log.lock().unwrap(),
            [
                ("chain_getBlock", hash_of_byte(0x42)),
                ("chain_getBlock", hash_of_byte(0x41))
            ]
        );
        rpc.block_emissions(&numbered_block_ref(0x42), &addr(0xab), &addr(0xcd))
            .await
            .unwrap();
        assert_eq!(
            log.lock().unwrap().last(),
            Some(&("chain_getBlock", hash_of_byte(0x42))),
            "a second processing of the block, as a retry makes, fetches it again"
        );
    }

    /// A block looked up by number that the node has no block for is read by its header.
    #[tokio::test]
    async fn a_block_looked_up_by_number_without_a_block_is_read_by_its_header() {
        let (rpc, _handle, log) = numbered_indexer_node(|_| serde_json::Value::Null).await;
        assert_eq!(
            rpc.block_ref_at(0x1af).await.unwrap(),
            numbered_block_ref(0x42)
        );
        assert_eq!(
            *log.lock().unwrap(),
            [
                ("chain_getBlock", hash_of_byte(0x42)),
                ("chain_getHeader", hash_of_byte(0x42))
            ]
        );
    }

    /// A node that has no block for its own finalized head: the head is read by its
    /// header, and processing it fails as a missing block.
    #[tokio::test]
    async fn a_head_without_a_block_is_read_by_its_header() {
        let (rpc, _handle, log) = numbered_indexer_node(|_| serde_json::Value::Null).await;
        assert_eq!(
            rpc.finalized_block_ref().await.unwrap(),
            numbered_block_ref(0x43)
        );
        assert_eq!(
            *log.lock().unwrap(),
            [
                ("chain_getBlock", hash_of_byte(0x43)),
                ("chain_getHeader", hash_of_byte(0x43))
            ]
        );
        let error = rpc
            .block_emissions(&numbered_block_ref(0x43), &addr(0xab), &addr(0xcd))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("has no block"), "{error:#}");
    }

    /// A moved head whose block cannot be read is read by its header: the poll goes on,
    /// and the block is fetched when the head is processed.
    #[tokio::test]
    async fn a_head_whose_block_read_fails_is_read_by_its_header() {
        let metadata = subxt::Metadata::decode_all(
            &mut &include_bytes!("../../fixtures/fallible-block-432-metadata.scale")[..],
        )
        .unwrap();
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let mut config = http_config(server.local_addr().unwrap());
        config.rpc.retry = attempts(0);
        let transport = connect_http(&config).unwrap();
        let client = OnlineClient::<SubstrateConfig>::from_rpc_client_with(
            H256([0x11; 32]),
            subxt::client::RuntimeVersion {
                spec_version: 1,
                transaction_version: 1,
            },
            metadata,
            transport.clone(),
        )
        .unwrap();
        let blocks = Arc::new(AtomicUsize::new(0));
        let mut module = RpcModule::new(());
        module
            .register_method("chain_getFinalizedHead", |_, _, _| hash_of_byte(0x43))
            .unwrap();
        let read = blocks.clone();
        module
            .register_method("chain_getBlock", move |_, _, _| {
                read.fetch_add(1, Ordering::SeqCst);
                Err::<serde_json::Value, _>(ErrorObjectOwned::owned(
                    -32000,
                    "the backend is behind",
                    None::<()>,
                ))
            })
            .unwrap();
        module
            .register_method("chain_getHeader", |params, _, _| {
                let [hash] = params.parse::<[String; 1]>().unwrap();
                assert_eq!(hash, hash_of_byte(0x43));
                json!({
                    "parentHash": hash_of_byte(0x42),
                    "number": "0x1b0",
                    "stateRoot": hash_of_byte(0x44),
                    "extrinsicsRoot": hash_of_byte(0x45),
                    "digest": { "logs": [] }
                })
            })
            .unwrap();
        let _handle = server.start(module);
        let rpc = MidnightRpc {
            client,
            reads: Reads::new(transport, config.rpc.request_timeout, config.rpc.retry),
            head: Default::default(),
            walked: Default::default(),
        };
        let at_0x43 = BlockRef {
            number: 0x1b0,
            hash: BlockHash::from_bytes([0x43; 32]),
            parent_hash: BlockHash::from_bytes([0x42; 32]),
        };

        assert_eq!(rpc.finalized_block_ref().await.unwrap(), at_0x43);
        assert_eq!(rpc.finalized_block_ref().await.unwrap(), at_0x43);
        assert_eq!(
            blocks.load(Ordering::SeqCst),
            1,
            "a standing head reads no block"
        );
        rpc.block_emissions(&at_0x43, &addr(0xab), &addr(0xcd))
            .await
            .expect_err("the block still cannot be read");
        assert_eq!(
            blocks.load(Ordering::SeqCst),
            2,
            "processing the head fetches its block"
        );
    }

    /// The indexer reads a standing finalized head's hash alone, and a moved head's
    /// block once: its number and parent come from `chain_getBlock`, and the
    /// emissions of that head take the same block. No `chain_getHeader` is served.
    #[tokio::test]
    async fn the_indexer_reads_each_finalized_head_block_once() {
        let metadata = subxt::Metadata::decode_all(
            &mut &include_bytes!("../../fixtures/fallible-block-432-metadata.scale")[..],
        )
        .unwrap();
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let mut config = http_config(server.local_addr().unwrap());
        config.rpc.retry = attempts(0);
        let transport = connect_http(&config).unwrap();
        let client = OnlineClient::<SubstrateConfig>::from_rpc_client_with(
            H256([0x11; 32]),
            subxt::client::RuntimeVersion {
                spec_version: 1,
                transaction_version: 1,
            },
            metadata,
            transport.clone(),
        )
        .unwrap();
        let head = Arc::new(std::sync::Mutex::new(hash_of_byte(0x43)));
        let heads = Arc::new(AtomicUsize::new(0));
        let blocks = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let mut module = RpcModule::new(());
        let (served, counted) = (head.clone(), heads.clone());
        module
            .register_method("chain_getFinalizedHead", move |_, _, _| {
                counted.fetch_add(1, Ordering::SeqCst);
                served.lock().unwrap().clone()
            })
            .unwrap();
        let read = blocks.clone();
        module
            .register_method("chain_getBlock", move |params, _, _| {
                let [hash] = params.parse::<[String; 1]>().unwrap();
                read.lock().unwrap().push(hash.clone());
                let (number, parent) = if hash == hash_of_byte(0x43) {
                    ("0x1b0", hash_of_byte(0x42))
                } else {
                    ("0x1b1", hash_of_byte(0x43))
                };
                json!({
                    "block": {
                        "header": {
                            "parentHash": parent,
                            "number": number,
                            "stateRoot": hash_of_byte(0x44),
                            "extrinsicsRoot": hash_of_byte(0x45),
                            "digest": { "logs": [] }
                        },
                        "extrinsics": []
                    },
                    "justifications": null
                })
            })
            .unwrap();
        let _handle = server.start(module);
        let rpc = MidnightRpc {
            client,
            reads: Reads::new(transport, config.rpc.request_timeout, config.rpc.retry),
            head: Default::default(),
            walked: Default::default(),
        };
        let at_0x43 = BlockRef {
            number: 0x1b0,
            hash: BlockHash::from_bytes([0x43; 32]),
            parent_hash: BlockHash::from_bytes([0x42; 32]),
        };

        assert_eq!(rpc.finalized_block_ref().await.unwrap(), at_0x43);
        assert_eq!(rpc.finalized_block_ref().await.unwrap(), at_0x43);
        assert_eq!(*blocks.lock().unwrap(), [hash_of_byte(0x43)]);
        assert_eq!(
            rpc.block_emissions(&at_0x43, &addr(0xab), &addr(0xcd))
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            *blocks.lock().unwrap(),
            [hash_of_byte(0x43)],
            "the head's emissions take the block its head read fetched"
        );
        rpc.block_emissions(&at_0x43, &addr(0xab), &addr(0xcd))
            .await
            .unwrap();
        assert_eq!(
            *blocks.lock().unwrap(),
            [hash_of_byte(0x43), hash_of_byte(0x43)],
            "a second read of the same block, as a retry makes, fetches it again"
        );

        *head.lock().unwrap() = hash_of_byte(0x46);
        assert_eq!(
            rpc.finalized_block_ref().await.unwrap(),
            BlockRef {
                number: 0x1b1,
                hash: BlockHash::from_bytes([0x46; 32]),
                parent_hash: BlockHash::from_bytes([0x43; 32]),
            }
        );
        assert_eq!(
            *blocks.lock().unwrap(),
            [hash_of_byte(0x43), hash_of_byte(0x43), hash_of_byte(0x46)]
        );
        assert_eq!(heads.load(Ordering::SeqCst), 3);
    }
}
