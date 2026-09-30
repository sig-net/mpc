use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{keccak256, Address, Bytes, U256};
use alloy::providers::ext::AnvilApi as _;
use alloy::providers::{Provider as _, ProviderBuilder};
use alloy::rpc::types::{TransactionInput, TransactionRequest};
use anyhow::Context as _;
use integration_tests::cluster;
use integration_tests::midnight::{CallPlacement, PlacementScenario};
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use mpc_chain_integration_core::utils::test::ChainIndexerStream;
use mpc_chain_integration_core::{MockStateManager, NoopChainTelemetry};
use mpc_chain_midnight::MidnightIndexer;
use mpc_node::sign_bidirectional::{derive_user_address, SignBidirectionalEventExt as _};
use mpc_primitives::{
    AttestationMetadata, AttestationOutcomeKind, Chain, ChainEvent, IndexedSignRequest,
    PublishedAttestation, SignKind,
};
use serde::Deserialize;
use serial_test::serial;
use test_log::test;

const EVENT_TIMEOUT: Duration = Duration::from_secs(8 * 60);
const RETURN_TRUE_RUNTIME_BYTECODE: &str = "600160005260206000f3";

struct OutputCase {
    name: String,
    runtime: Bytes,
    argument: [u8; 32],
    output_schema: Vec<u8>,
    response_schema: Vec<u8>,
    expected_output: Vec<u8>,
    expected_call_result: Option<Bytes>,
    failed: bool,
    cache_outage: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OutputVector {
    name: String,
    output_schema_hex: String,
    respond_schema_hex: String,
    call_result_hex: String,
    expected_output_hex: Option<String>,
}

fn output_cases() -> anyhow::Result<Vec<OutputCase>> {
    let mut cases = Vec::new();
    for (output_type, width, failed) in [
        ("bool", 1, false),
        ("uint64", 8, false),
        ("bytes32", 32, false),
        ("uint64", 0, true),
    ] {
        let schema = serde_json::to_vec(&serde_json::json!([
            {"name": "success", "type": output_type}
        ]))?;
        let mut expected_output = vec![0; width];
        if !failed {
            expected_output[if output_type == "bytes32" { 31 } else { 0 }] = 1;
        }
        let mut argument = [0; 32];
        argument[31] = 6;
        cases.push(OutputCase {
            name: if failed { "reverted" } else { output_type }.into(),
            runtime: hex::decode(if failed {
                "60006000fd"
            } else {
                RETURN_TRUE_RUNTIME_BYTECODE
            })?
            .into(),
            argument,
            output_schema: schema.clone(),
            response_schema: schema,
            expected_output,
            expected_call_result: None,
            failed,
            cache_outage: false,
        });
    }

    #[derive(Deserialize)]
    struct Oracle {
        vectors: Vec<OutputVector>,
    }
    let oracle: Oracle = serde_json::from_str(include_str!(
        "../../../chain-signatures/chain-ethereum/tests/fixtures/midnight_respond_vectors.json"
    ))?;
    for (name, contract, variant, cache_outage) in [
        (
            "UTF-8 string uses byte length and maxBytes capacity",
            "MidnightStringOutput",
            0,
            false,
        ),
        (
            "dynamic bytes use length and maxBytes capacity",
            "MidnightBytesOutput",
            0,
            false,
        ),
        (
            "dynamic ABI array maps into fixed-capacity response array",
            "MidnightArrayOutput",
            0,
            false,
        ),
        (
            "dynamic bytes exactly fill maxBytes capacity",
            "MidnightBytesOutput",
            1,
            false,
        ),
        (
            "empty dynamic bytes retain maxBytes capacity",
            "MidnightBytesOutput",
            2,
            true,
        ),
    ] {
        let vector = oracle
            .vectors
            .iter()
            .find(|vector| vector.name == name)
            .with_context(|| format!("missing SDK oracle case: {name}"))?;
        let artifact = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../chain-signatures/contract-eth/artifacts/contracts/MidnightConformance.sol/{contract}.json"
        ));
        let artifact: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&artifact)
                .with_context(|| format!("reading {}; run just build eth", artifact.display()))?,
        )?;
        let runtime = artifact["deployedBytecode"]
            .as_str()
            .context("Solidity fixture has no deployed bytecode")?;
        let mut argument = [0; 32];
        argument[31] = variant;
        cases.push(OutputCase {
            name: name.into(),
            runtime: hex::decode(runtime.trim_start_matches("0x"))?.into(),
            argument,
            output_schema: hex::decode(&vector.output_schema_hex)?,
            response_schema: hex::decode(&vector.respond_schema_hex)?,
            expected_output: hex::decode(
                vector
                    .expected_output_hex
                    .as_ref()
                    .context("live output case must be accepted by the SDK")?,
            )?,
            expected_call_result: Some(hex::decode(&vector.call_result_hex)?.into()),
            failed: false,
            cache_outage,
        });
    }
    Ok(cases)
}

async fn wait_for_completed_checkpoint(
    cluster: &cluster::Cluster,
    request_id: [u8; 32],
    minimum_height: u64,
) -> anyhow::Result<()> {
    tokio::time::timeout(EVENT_TIMEOUT, async {
        loop {
            let mut complete = true;
            for node in 0..cluster.len() {
                match cluster.nodes.fetch_checkpoint(node, Chain::Midnight).await {
                    Ok(checkpoint) => {
                        complete &= checkpoint.block_height >= minimum_height
                            && checkpoint
                                .pending_requests
                                .iter()
                                .all(|pending| pending.sign_id().request_id != request_id);
                    }
                    Err(_) => complete = false,
                }
            }
            if complete {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await
    .context("timed out waiting for every MPC node to checkpoint final Midnight completion")??;
    Ok(())
}

#[ignore = "starts a real Midnight node, indexer, proof server, Anvil, and MPC cluster"]
#[serial]
#[test(tokio::test)]
async fn midnight_to_ethereum_to_midnight_consumes_caller_response() -> anyhow::Result<()> {
    let cases = output_cases()?;
    let next_nonce = cases.len() as u64;
    let cluster = cluster::spawn().ethereum().midnight().await?;
    cluster.wait().signable().await?;
    let midnight = cluster
        .midnight
        .as_ref()
        .context("Midnight context was not started")?;
    let indexer = MidnightIndexer::new(
        midnight.config.clone(),
        MockStateManager::new(),
        NoopChainTelemetry,
    )
    .await?;
    let mut events = ChainIndexerStream::start(indexer, EVENT_TIMEOUT).await?;

    let ethereum = cluster
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("Ethereum context was not started")?;
    let anvil =
        ProviderBuilder::new().connect_http(ethereum.sandbox.external_http_endpoint.parse()?);
    for (nonce, case) in cases.into_iter().enumerate() {
        tracing::info!(case = case.name, nonce, "checking Midnight API conformance");
        let target = Address::repeat_byte(0x42 + nonce as u8);
        anvil.anvil_set_code(target, case.runtime).await?;
        let mut expected_input = hex::decode("2a2e1320")?;
        expected_input.extend_from_slice(&case.argument);
        if let Some(expected_call_result) = &case.expected_call_result {
            let result = anvil
                .call(
                    TransactionRequest::default()
                        .to(target)
                        .input(TransactionInput::new(expected_input.clone().into())),
                )
                .await?;
            assert_eq!(
                &result, expected_call_result,
                "{}: Solidity ABI output differs from the SDK oracle",
                case.name
            );
        }
        let submitted = midnight
            .submit_is_even_with_schemas(
                nonce as u64,
                target.into_array(),
                case.argument,
                &case.output_schema,
                &case.response_schema,
            )
            .await?;
        anyhow::ensure!(
            notification_phase(&submitted.placement, &submitted.request_id) == Some("guaranteed"),
            "{}: the caller request must notify in the guaranteed transcript",
            case.name
        );
        let ChainEvent::SignRequest { request, .. } = events
            .wait_for(
                |event| {
                    matches!(
                        event,
                        ChainEvent::SignRequest { request, .. }
                            if request.chain == Chain::Midnight
                                && matches!(request.kind, SignKind::SignBidirectional(_))
                    )
                },
                EVENT_TIMEOUT,
            )
            .await
            .context("waiting for the caller SignRequest")?
        else {
            unreachable!("filtered above")
        };
        let request_id = request.id.request_id;
        assert_eq!(hex::encode(request_id), submitted.request_id);
        let SignKind::SignBidirectional(sign_event) = &request.kind else {
            unreachable!("filtered above")
        };
        assert_eq!(sign_event.caip2_id, Chain::Ethereum.caip2_chain_id());

        events
        .wait_for(
            |event| matches!(event, ChainEvent::Respond(response) if response.request_id == request_id),
            EVENT_TIMEOUT,
        )
        .await
        .context("waiting for the finalized respond entry")?;
        let root_public_key =
            mpc_crypto::near_public_key_to_affine_point(cluster.root_public_key().await?);
        let expected_sender = derive_user_address(root_public_key, sign_event.epsilon()?);
        let signed = midnight
            .signed_evm_transaction(request_id, &format!("{expected_sender:#x}"))
            .await?;
        assert_eq!(signed.from.parse::<Address>()?, expected_sender);
        assert_eq!(signed.to.parse::<Address>()?, target);
        assert_eq!(signed.chain_id, "31337");
        assert_eq!(
            signed.unsigned_hash,
            format!("{:#x}", keccak256(&sign_event.serialized_transaction))
        );
        assert_eq!(
            hex::decode(signed.data.trim_start_matches("0x"))?,
            expected_input
        );
        anvil
            .anvil_set_balance(expected_sender, U256::from(10_000_000_000_000_000_000u128))
            .await?;
        if case.cache_outage {
            // Accepted deviation: configured-cache failure does not gate publication.
            // This final output case leaves the test-owned cache unavailable.
            midnight.output_storage.stop().await?;
        }
        let pending = anvil
            .send_raw_transaction(&hex::decode(signed.serialized.trim_start_matches("0x"))?)
            .await?;
        let receipt = pending.get_receipt().await?;
        assert_eq!(
            receipt.status(),
            !case.failed,
            "unexpected EVM execution status"
        );

        let response_event = events
        .wait_for(
            |event| {
                matches!(
                    event,
                    ChainEvent::RespondBidirectional(response) if response.request_id == request_id
                )
            },
            EVENT_TIMEOUT,
        )
        .await
        .context("waiting for the finalized respondBidirectional entry")?;
        let ChainEvent::RespondBidirectional(response_event) = response_event else {
            unreachable!()
        };
        let metadata = response_event
            .attestation
            .context("Midnight event has no attestation metadata")?;
        let output = if case.cache_outage {
            let error = midnight.stored_output(request_id).await.unwrap_err();
            assert!(
                error
                    .downcast_ref::<reqwest::Error>()
                    .is_some_and(reqwest::Error::is_connect),
                "expected unavailable configured cache, got {error:#}"
            );
            // The independently checked Solidity/SDK output still settles the
            // published attestation, without claiming cache recovery succeeded.
            case.expected_output.clone()
        } else {
            midnight.stored_output(request_id).await?
        };
        assert_eq!(metadata.serialized_output_length, output.len() as u64);
        let signing_metadata = mpc_primitives::AttestationMetadata {
            key_version: sign_event.key_version,
            block_height: metadata.block_height,
            outcome_kind: metadata.outcome_kind,
        };
        assert_eq!(
            metadata.digest,
            mpc_compact_hashing::compute_attestation_hash(&request_id, &signing_metadata, &output)?
        );
        assert_eq!(
            metadata.block_height,
            receipt
                .block_number
                .context("receipt has no inclusion height")?
        );
        assert_eq!(
            metadata.outcome_kind,
            if case.failed {
                mpc_primitives::AttestationOutcomeKind::Failed
            } else {
                mpc_primitives::AttestationOutcomeKind::Executed
            }
        );
        assert_eq!(
            output, case.expected_output,
            "{}: output bytes differ",
            case.name
        );
        midnight
            .settle_response(request_id, &output, case.failed)
            .await?;
        let ChainEvent::Block(final_block) = events
            .wait_for(|event| matches!(event, ChainEvent::Block(_)), EVENT_TIMEOUT)
            .await
            .context("waiting for a block after respondBidirectional")?
        else {
            unreachable!("filtered above")
        };
        wait_for_completed_checkpoint(&cluster, request_id, final_block).await?;
    }

    // Impersonation: another contract notifies the central Signet contract naming the caller's
    // filed, still-pending request. Blocks index in order, so the next sign request seen after
    // a later genuine submission must be that submission, never the impersonated one.
    let mut argument = [0; 32];
    argument[31] = 6;
    let mut next_sign_request = async || {
        let ChainEvent::SignRequest { request, .. } = events
            .wait_for(
                |event| {
                    matches!(event, ChainEvent::SignRequest { request, .. }
                        if request.chain == Chain::Midnight)
                },
                EVENT_TIMEOUT,
            )
            .await?
        else {
            unreachable!("filtered above")
        };
        anyhow::Ok(request)
    };
    midnight
        .submit_is_even(next_nonce, [0x50; 20], argument, "bool")
        .await?;
    let victim_request = next_sign_request()
        .await
        .context("waiting for the victim's genuine SignRequest")?;
    let victim_id = victim_request.id.request_id;
    midnight.notify_as_caller(victim_id).await?;
    midnight
        .submit_is_even(next_nonce, [0x51; 20], argument, "bool")
        .await?;
    let after_impersonation = next_sign_request()
        .await
        .context("waiting for the SignRequest after the impersonation")?;
    assert_ne!(
        after_impersonation.id.request_id, victim_id,
        "a notification from a contract other than the named caller was indexed"
    );

    // Two signed requests occupy one EVM nonce. Executing the replacement must
    // attest both its output and the displaced request at the same inclusion height.
    let root_public_key =
        mpc_crypto::near_public_key_to_affine_point(cluster.root_public_key().await?);
    let mut replacement_height = None;
    for request in [&victim_request, &after_impersonation] {
        let SignKind::SignBidirectional(sign_event) = &request.kind else {
            anyhow::bail!("expected a bidirectional request");
        };
        let expected_sender = derive_user_address(root_public_key, sign_event.epsilon()?);
        let signed = midnight
            .signed_evm_transaction(request.id.request_id, &format!("{expected_sender:#x}"))
            .await?;
        if request.id.request_id == victim_id {
            continue;
        }
        anvil
            .anvil_set_code(
                Address::repeat_byte(0x51),
                hex::decode(RETURN_TRUE_RUNTIME_BYTECODE)?.into(),
            )
            .await?;
        let receipt = anvil
            .send_raw_transaction(&hex::decode(signed.serialized.trim_start_matches("0x"))?)
            .await?
            .get_receipt()
            .await?;
        assert!(
            receipt.status(),
            "replacement must consume the nonce successfully"
        );
        replacement_height = receipt.block_number;
    }
    let replacement_height = replacement_height.context("replacement receipt has no height")?;
    let replacement_id = after_impersonation.id.request_id;
    let mut victim_attested = false;
    let mut replacement_attested = false;
    // Collect both responses before settling either: publication order is not
    // specified, and waiting for settlement blocks would consume the other event.
    while !victim_attested || !replacement_attested {
        let response = events
            .wait_for(
                |event| {
                    matches!(event, ChainEvent::RespondBidirectional(response)
                    if (response.request_id == victim_id && !victim_attested)
                        || (response.request_id == replacement_id && !replacement_attested))
                },
                EVENT_TIMEOUT,
            )
            .await
            .context("waiting for replacement and displaced-request attestations")?;
        let ChainEvent::RespondBidirectional(response) = response else {
            unreachable!()
        };
        let (request, output, outcome) = if response.request_id == victim_id {
            victim_attested = true;
            (
                &victim_request,
                &[][..],
                mpc_primitives::AttestationOutcomeKind::Unviable,
            )
        } else {
            replacement_attested = true;
            (
                &after_impersonation,
                &[1][..],
                mpc_primitives::AttestationOutcomeKind::Executed,
            )
        };
        let SignKind::SignBidirectional(sign_event) = &request.kind else {
            unreachable!("both requests were checked above")
        };
        let metadata = response
            .attestation
            .context("Midnight event has no attestation metadata")?;
        assert_eq!(metadata.block_height, replacement_height);
        assert_eq!(metadata.outcome_kind, outcome);
        assert_eq!(metadata.serialized_output_length, output.len() as u64);
        assert_eq!(
            metadata.digest,
            mpc_compact_hashing::compute_attestation_hash(
                &response.request_id,
                &mpc_primitives::AttestationMetadata {
                    key_version: sign_event.key_version,
                    block_height: replacement_height,
                    outcome_kind: outcome,
                },
                output,
            )?
        );
    }
    // The zero-width caller circuit accepts Unviable and rejects padded/replayed
    // responses using the same signature checks as a finalized EVM revert.
    midnight.settle_response(victim_id, &[], true).await?;
    midnight
        .settle_response(replacement_id, &[1], false)
        .await?;
    let ChainEvent::Block(final_block) = events
        .wait_for(|event| matches!(event, ChainEvent::Block(_)), EVENT_TIMEOUT)
        .await?
    else {
        unreachable!()
    };
    wait_for_completed_checkpoint(&cluster, victim_id, final_block).await?;
    wait_for_completed_checkpoint(&cluster, replacement_id, final_block).await?;

    midnight.shutdown().await?;
    Ok(())
}

/// Midnight events the test's own indexer emitted, recorded in arrival order so waiting
/// for one kind never discards another.
#[derive(Default)]
struct Observed {
    sign_requests: Vec<Arc<IndexedSignRequest>>,
    responded: BTreeSet<[u8; 32]>,
    attested: BTreeMap<[u8; 32], PublishedAttestation>,
    block: Option<u64>,
}

impl Observed {
    fn record(&mut self, event: ChainEvent) {
        match event {
            ChainEvent::SignRequest { request, .. } if request.chain == Chain::Midnight => {
                self.sign_requests.push(request);
            }
            ChainEvent::Respond(response) if response.chain == Chain::Midnight => {
                self.responded.insert(response.request_id);
            }
            ChainEvent::RespondBidirectional(response) if response.chain == Chain::Midnight => {
                if let Some(attestation) = response.attestation {
                    self.attested.insert(response.request_id, attestation);
                }
            }
            ChainEvent::Block(height) => self.block = Some(height),
            _ => {}
        }
    }

    async fn until(
        &mut self,
        events: &mut ChainIndexerStream,
        what: &str,
        done: impl Fn(&Self) -> bool,
    ) -> anyhow::Result<()> {
        tokio::time::timeout(EVENT_TIMEOUT, async {
            while !done(self) {
                let event = events
                    .next_event()
                    .await
                    .context("Midnight indexer stopped")?;
                self.record(event);
            }
            anyhow::Ok(())
        })
        .await
        .with_context(|| format!("timed out waiting for {what}"))?
    }

    fn indexed(&self) -> Vec<[u8; 32]> {
        self.sign_requests
            .iter()
            .map(|request| request.id.request_id)
            .collect()
    }

    /// A block indexed after everything recorded so far.
    async fn next_block(&mut self, events: &mut ChainIndexerStream) -> anyhow::Result<u64> {
        self.block = None;
        self.until(events, "a later Midnight block", |observed| {
            observed.block.is_some()
        })
        .await?;
        self.block.context("recorded block")
    }
}

fn request_id(encoded: &str) -> anyhow::Result<[u8; 32]> {
    let mut request_id = [0; 32];
    hex::decode_to_slice(encoded.trim_start_matches("0x"), &mut request_id)
        .with_context(|| format!("invalid request id {encoded}"))?;
    Ok(request_id)
}

/// The transcript phase that emits `request_id`'s singleton notification.
fn notification_phase(placement: &[CallPlacement], request_id: &str) -> Option<&'static str> {
    placement.iter().find_map(|call| {
        if call
            .guaranteed_notifications
            .iter()
            .any(|id| id == request_id)
        {
            Some("guaranteed")
        } else if call
            .fallible_notifications
            .iter()
            .any(|id| id == request_id)
        {
            Some("fallible")
        } else {
            None
        }
    })
}

fn expect_executed_attestation(
    request_id: &[u8; 32],
    attestation: &PublishedAttestation,
    block_height: u64,
    output: &[u8],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        attestation.block_height == block_height
            && attestation.outcome_kind == AttestationOutcomeKind::Executed
            && attestation.serialized_output_length == output.len() as u64,
        "{}: unexpected attestation {attestation:?} for block {block_height}",
        hex::encode(request_id)
    );
    let metadata = AttestationMetadata {
        key_version: mpc_primitives::LATEST_MPC_KEY_VERSION,
        block_height,
        outcome_kind: AttestationOutcomeKind::Executed,
    };
    anyhow::ensure!(
        attestation.digest
            == mpc_compact_hashing::compute_attestation_hash(request_id, &metadata, output)?,
        "{}: attestation digest does not bind the executed output",
        hex::encode(request_id)
    );
    Ok(())
}

#[ignore = "starts a real Midnight node, indexer, proof server, Anvil, and MPC cluster"]
#[serial]
#[test(tokio::test)]
async fn midnight_indexes_notifications_by_transcript_placement() -> anyhow::Result<()> {
    let cluster = cluster::spawn().ethereum().midnight().await?;
    cluster.wait().signable().await?;
    let midnight = cluster
        .midnight
        .as_ref()
        .context("Midnight context was not started")?;
    let indexer = MidnightIndexer::new(
        midnight.config.clone(),
        MockStateManager::new(),
        NoopChainTelemetry,
    )
    .await?;
    let mut events = ChainIndexerStream::start(indexer, EVENT_TIMEOUT).await?;
    let ethereum = cluster
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("Ethereum context was not started")?;
    let anvil =
        ProviderBuilder::new().connect_http(ethereum.sandbox.external_http_endpoint.parse()?);
    let target = Address::repeat_byte(0x61);
    anvil
        .anvil_set_code(target, hex::decode(RETURN_TRUE_RUNTIME_BYTECODE)?.into())
        .await?;
    let mut argument = [0; 32];
    argument[31] = 6;

    // The driver checks each transaction's placement before submitting it; the phases
    // below are the requests' in call order.
    let scenarios = [
        (PlacementScenario::FallibleOnly, &["fallible"][..]),
        (
            PlacementScenario::GuaranteedTranscriptPair,
            &["guaranteed", "guaranteed"][..],
        ),
        (
            PlacementScenario::FallibleTranscriptPair,
            &["fallible", "fallible"][..],
        ),
        (
            PlacementScenario::GuaranteedThenFallibleSegments,
            &["guaranteed", "fallible"][..],
        ),
        (
            PlacementScenario::FallibleSegmentPair,
            &["fallible", "fallible"][..],
        ),
    ];
    let mut nonces = BTreeMap::new();
    let mut expected = Vec::new();
    for (scenario, phases) in scenarios {
        let first_nonce = nonces.len() as u64;
        let calls = (first_nonce..first_nonce + phases.len() as u64)
            .map(|nonce| (nonce, target.into_array()))
            .collect::<Vec<_>>();
        let outcome = midnight
            .submit_placement(scenario, &calls, argument)
            .await?;
        tracing::info!(?scenario, notifications = ?outcome.notifications, "placement submitted");
        anyhow::ensure!(
            outcome.status == "SucceedEntirely" && outcome.committed == outcome.requests,
            "{scenario:?} did not apply every request: {outcome:?}"
        );
        for ((request, phase), (nonce, _)) in outcome.requests.iter().zip(phases).zip(&calls) {
            anyhow::ensure!(
                notification_phase(&outcome.placement, request) == Some(*phase),
                "{scenario:?} did not notify {request} in the {phase} transcript"
            );
            nonces.insert(request_id(request)?, *nonce);
        }
        if scenario == PlacementScenario::FallibleSegmentPair {
            // The second request's intent has the lower segment, so the ledger applies it first.
            let reversed = outcome.requests.iter().rev().cloned().collect::<Vec<_>>();
            anyhow::ensure!(
                outcome.notifications == reversed,
                "fallible segments were not ordered by segment: {outcome:?}"
            );
        }
        for notification in &outcome.notifications {
            expected.push(request_id(notification)?);
        }
    }

    // A guaranteed intent commits while the fallible intent after it fails. The MPC indexes
    // only fully applied transactions, so neither request is ever signed; their nonces lie
    // beyond the executed range.
    let partial = midnight
        .submit_placement(
            PlacementScenario::PartialSuccess,
            &[(1_000, target.into_array()), (1_001, target.into_array())],
            argument,
        )
        .await?;
    anyhow::ensure!(
        partial.status == "FailFallible" && partial.committed == partial.requests[..1],
        "expected only the guaranteed intent to commit: {partial:?}"
    );
    let skipped = partial
        .requests
        .iter()
        .map(|id| request_id(id))
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Blocks index in order, so once this later request is indexed every earlier
    // notification has been indexed or skipped.
    let sentinel = midnight
        .submit_is_even(nonces.len() as u64, target.into_array(), argument, "bool")
        .await?;
    anyhow::ensure!(
        notification_phase(&sentinel.placement, &sentinel.request_id) == Some("guaranteed"),
        "a plain caller request must notify in the guaranteed transcript"
    );
    let sentinel_id = request_id(&sentinel.request_id)?;
    nonces.insert(sentinel_id, nonces.len() as u64);
    expected.push(sentinel_id);
    let mut observed = Observed::default();
    observed
        .until(&mut events, "the sentinel SignRequest", |observed| {
            observed.indexed().contains(&sentinel_id)
        })
        .await?;
    anyhow::ensure!(
        observed.indexed() == expected,
        "indexed {:?}, expected {:?}",
        observed
            .indexed()
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>(),
        expected.iter().map(hex::encode).collect::<Vec<_>>()
    );

    let root_public_key =
        mpc_crypto::near_public_key_to_affine_point(cluster.root_public_key().await?);
    let SignKind::SignBidirectional(sign_event) = &observed.sign_requests[0].kind else {
        anyhow::bail!("expected a bidirectional request");
    };
    let sender = derive_user_address(root_public_key, sign_event.epsilon()?);
    anvil
        .anvil_set_balance(sender, U256::from(10_000_000_000_000_000_000u128))
        .await?;
    let mut heights = BTreeMap::new();
    let mut by_nonce = nonces
        .iter()
        .map(|(id, nonce)| (*nonce, *id))
        .collect::<Vec<_>>();
    by_nonce.sort();
    for (_, id) in by_nonce {
        observed
            .until(&mut events, "the MPC signature", |observed| {
                observed.responded.contains(&id)
            })
            .await?;
        let signed = midnight
            .signed_evm_transaction(id, &format!("{sender:#x}"))
            .await?;
        let receipt = anvil
            .send_raw_transaction(&hex::decode(signed.serialized.trim_start_matches("0x"))?)
            .await?
            .get_receipt()
            .await?;
        anyhow::ensure!(receipt.status(), "{} reverted", hex::encode(id));
        heights.insert(
            id,
            receipt
                .block_number
                .context("receipt has no inclusion height")?,
        );
    }
    observed
        .until(&mut events, "every attestation", |observed| {
            expected.iter().all(|id| observed.attested.contains_key(id))
        })
        .await?;
    for id in &expected {
        expect_executed_attestation(id, &observed.attested[id], heights[id], &[1])?;
    }
    let final_block = observed.next_block(&mut events).await?;
    for id in expected.iter().chain(&skipped) {
        wait_for_completed_checkpoint(&cluster, *id, final_block).await?;
    }
    anyhow::ensure!(
        skipped
            .iter()
            .all(|id| !observed.responded.contains(id) && !observed.indexed().contains(id)),
        "a request from the partially successful transaction was signed"
    );

    midnight.shutdown().await?;
    Ok(())
}

#[ignore = "starts a real Midnight node, indexer, proof server, Anvil, and MPC cluster"]
#[serial]
#[test(tokio::test)]
async fn midnight_vault_operations_complete_with_real_mpc() -> anyhow::Result<()> {
    let cluster = cluster::spawn().ethereum().midnight().await?;
    cluster.wait().signable().await?;
    let midnight = cluster
        .midnight
        .as_ref()
        .context("Midnight context was not started")?;
    let ethereum = cluster
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("Ethereum context was not started")?;
    let indexer = MidnightIndexer::new(
        midnight.config.clone(),
        MockStateManager::new(),
        NoopChainTelemetry,
    )
    .await?;
    let mut events = ChainIndexerStream::start(indexer, EVENT_TIMEOUT).await?;
    let root_public_key =
        mpc_crypto::near_public_key_to_affine_point(cluster.root_public_key().await?);
    let mpc_public_key = format!(
        "0x{}",
        hex::encode(root_public_key.to_encoded_point(false).as_bytes())
    );

    let mut observed = Observed::default();
    let run = midnight.run_vault(
        &mpc_public_key,
        &ethereum.sandbox.external_http_endpoint,
        &ethereum.sandbox.secret_key,
    );
    tokio::pin!(run);
    let result = tokio::time::timeout(Duration::from_secs(60 * 60), async {
        loop {
            tokio::select! {
                result = &mut run => return result,
                event = events.next_event() => {
                    observed.record(event.context("Midnight indexer stopped during the vault run")?);
                }
            }
        }
    })
    .await
    .context("the vault run exceeded an hour")??;

    let operations = result
        .operations
        .iter()
        .map(|operation| operation.operation.as_str())
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        operations
            == BTreeSet::from([
                "deposit",
                "approveRouter",
                "approveStata",
                "withdraw",
                "swap",
                "supply",
                "redeem",
            ])
            && result.operations.len() == operations.len(),
        "unexpected vault operations {operations:?}"
    );
    let mut request_ids = BTreeSet::new();
    for operation in &result.operations {
        // The vault's send circuits exceed the guaranteed budget, so every notification
        // comes from a fallible transcript of a fully applied transaction.
        anyhow::ensure!(
            notification_phase(&operation.placement, &operation.request_id) == Some("fallible"),
            "{} did not notify in the fallible transcript: {:?}",
            operation.operation,
            operation.placement
        );
        anyhow::ensure!(
            request_ids.insert(request_id(&operation.request_id)?),
            "the vault repeated a request id"
        );
    }
    observed
        .until(&mut events, "every vault request's events", |observed| {
            request_ids.iter().all(|id| {
                observed.indexed().contains(id)
                    && observed.responded.contains(id)
                    && observed.attested.contains_key(id)
            })
        })
        .await?;
    for operation in &result.operations {
        let id = request_id(&operation.request_id)?;
        expect_executed_attestation(
            &id,
            &observed.attested[&id],
            operation.evm_block_height,
            &hex::decode(&operation.output)?,
        )?;
    }
    let final_block = observed.next_block(&mut events).await?;
    for id in &request_ids {
        wait_for_completed_checkpoint(&cluster, *id, final_block).await?;
    }
    midnight.shutdown().await?;
    Ok(())
}
