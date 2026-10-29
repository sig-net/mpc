use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{keccak256, Address, Bytes, U256};
use alloy::providers::ext::AnvilApi as _;
use alloy::providers::{Provider as _, ProviderBuilder};
use alloy::rpc::types::{TransactionInput, TransactionRequest};
use anyhow::Context as _;
use integration_tests::cluster;
use integration_tests::midnight::{AdversarialScenario, CallPlacement, PlacementScenario};
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
    output_schema: Vec<u8>,
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
    is_contract_call: bool,
    trace: OutputTrace,
    expected_output_hex: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OutputTrace {
    return_data_hex: Option<String>,
}

fn output_cases() -> anyhow::Result<Vec<OutputCase>> {
    let mut cases = Vec::new();
    // The target returns the ABI word 1. A uint256 is attested little-endian, a bytes32 in
    // wire order, and a reverted call attests an empty output.
    for (output_type, expected_output, failed) in [
        ("bool", "01".to_string(), false),
        ("uint256", format!("01{}", "00".repeat(31)), false),
        ("bytes32", format!("{}01", "00".repeat(31)), false),
        ("uint256", String::new(), true),
    ] {
        cases.push(OutputCase {
            name: if failed { "reverted" } else { output_type }.into(),
            runtime: hex::decode(if failed {
                "60006000fd"
            } else {
                RETURN_TRUE_RUNTIME_BYTECODE
            })?
            .into(),
            output_schema: serde_json::to_vec(&serde_json::json!([
                {"name": "success", "type": output_type}
            ]))?,
            expected_output: hex::decode(expected_output)?,
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
        "../../../chain-signatures/midnight-respond-codec/tests/fixtures/midnight_respond_vectors.json"
    ))?;
    for (name, contract, cache_outage) in [
        (
            "uint256 340282366920938463463374607431768211456 is little-endian",
            "MidnightUint256Output",
            false,
        ),
        (
            "address keeps wire byte order",
            "MidnightAddressOutput",
            false,
        ),
        (
            "bytes12 then address keep schema order in a 64-byte schema",
            "MidnightTagThenAddressOutput",
            false,
        ),
        (
            "trailing words past the last field are ignored",
            "MidnightTrailingWordOutput",
            true,
        ),
    ] {
        let vector = oracle
            .vectors
            .iter()
            .find(|vector| vector.name == name)
            .with_context(|| format!("missing SDK oracle case: {name}"))?;
        anyhow::ensure!(vector.is_contract_call, "{name}: not a contract call");
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
        cases.push(OutputCase {
            name: name.into(),
            runtime: hex::decode(runtime.trim_start_matches("0x"))?.into(),
            output_schema: hex::decode(&vector.output_schema_hex)?,
            expected_output: hex::decode(
                vector
                    .expected_output_hex
                    .as_ref()
                    .context("live output case must be accepted by the SDK")?,
            )?,
            expected_call_result: Some(
                hex::decode(
                    vector
                        .trace
                        .return_data_hex
                        .as_ref()
                        .context("live output case must have return data")?,
                )?
                .into(),
            ),
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
    let root_pk = mpc_crypto::near_public_key_to_affine_point(cluster.root_public_key().await?);
    let indexer = MidnightIndexer::new(
        midnight.config.clone(),
        MockStateManager::new(),
        NoopChainTelemetry,
        root_pk,
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
    let mut argument = [0; 32];
    argument[31] = 6;
    for (nonce, case) in cases.into_iter().enumerate() {
        tracing::info!(case = case.name, nonce, "checking Midnight API conformance");
        let target = Address::repeat_byte(0x42 + nonce as u8);
        anvil.anvil_set_code(target, case.runtime).await?;
        let mut expected_input = hex::decode("2a2e1320")?;
        expected_input.extend_from_slice(&argument);
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
            .submit_is_even_with_schema(
                nonce as u64,
                target.into_array(),
                argument,
                &case.output_schema,
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
        let expected_sender = derive_user_address(root_pk, sign_event.epsilon()?);
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
    let root_public_key =
        mpc_crypto::near_public_key_to_affine_point(cluster.root_public_key().await?);
    let indexer = MidnightIndexer::new(
        midnight.config.clone(),
        MockStateManager::new(),
        NoopChainTelemetry,
        root_public_key,
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

    // Partially successful transactions: the node does not say which fallible segments
    // committed. A request whose segment committed is signed; one whose segment rolled
    // back never is, so its nonce lies beyond the executed range.
    let mut skipped = Vec::new();
    for (scenario, committed_phase) in [
        (PlacementScenario::PartialSuccess, "guaranteed"),
        (PlacementScenario::FallibleThenFailing, "fallible"),
    ] {
        let nonce = nonces.len() as u64;
        let rolled_back_nonce = 1_000 + skipped.len() as u64;
        let partial = midnight
            .submit_placement(
                scenario,
                &[
                    (nonce, target.into_array()),
                    (rolled_back_nonce, target.into_array()),
                ],
                argument,
            )
            .await?;
        anyhow::ensure!(
            partial.status == "FailFallible" && partial.committed == partial.requests[..1],
            "{scenario:?}: expected only the first intent to commit: {partial:?}"
        );
        anyhow::ensure!(
            notification_phase(&partial.placement, &partial.requests[0]) == Some(committed_phase),
            "{scenario:?} did not notify the committed request in the {committed_phase} transcript"
        );
        let committed = request_id(&partial.requests[0])?;
        nonces.insert(committed, nonce);
        expected.push(committed);
        skipped.push(request_id(&partial.requests[1])?);
    }
    // A fallible call proven before its request is filed by another transaction, and applied
    // after it, rolls back while naming a filed request. Only the filing is indexed.
    let nonce = nonces.len() as u64;
    let replay = midnight
        .submit_placement(
            PlacementScenario::RolledBackReplay,
            &[(nonce, target.into_array())],
            argument,
        )
        .await?;
    anyhow::ensure!(
        replay.status == "FailFallible" && replay.committed == replay.requests,
        "expected the replay to roll back after its request was filed: {replay:?}"
    );
    let replayed = request_id(&replay.requests[0])?;
    nonces.insert(replayed, nonce);
    expected.push(replayed);

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
    let root_public_key =
        mpc_crypto::near_public_key_to_affine_point(cluster.root_public_key().await?);
    let indexer = MidnightIndexer::new(
        midnight.config.clone(),
        MockStateManager::new(),
        NoopChainTelemetry,
        root_public_key,
    )
    .await?;
    let mut events = ChainIndexerStream::start(indexer, EVENT_TIMEOUT).await?;
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
    let result = tokio::time::timeout(Duration::from_secs(45 * 60), async {
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
    .context("the vault run exceeded 45 minutes")??;

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
        // Whether a send stays within the guaranteed budget depends on its circuit and the
        // ledger state, so a notification may come from either transcript; the placement
        // test pins both. Each must come from the transaction that sent it.
        let phase = notification_phase(&operation.placement, &operation.request_id);
        tracing::info!(
            operation = operation.operation,
            ?phase,
            "vault request notified"
        );
        anyhow::ensure!(
            phase.is_some(),
            "{} did not notify in its own transaction: {:?}",
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

/// Partially successful transaction shapes from the partial-success security review, on the
/// real stack. The reader decides from the caller's state at the block and its parent, so
/// each shape pins one decision that state can or cannot make.
#[ignore = "starts a real Midnight node, indexer, proof server, Anvil, and MPC cluster"]
#[serial]
#[test(tokio::test)]
async fn midnight_partial_success_review_shapes() -> anyhow::Result<()> {
    let cluster = cluster::spawn().ethereum().midnight().await?;
    cluster.wait().signable().await?;
    let midnight = cluster
        .midnight
        .as_ref()
        .context("Midnight context was not started")?;
    let root_public_key =
        mpc_crypto::near_public_key_to_affine_point(cluster.root_public_key().await?);
    let indexer = MidnightIndexer::new(
        midnight.config.clone(),
        MockStateManager::new(),
        NoopChainTelemetry,
        root_public_key,
    )
    .await?;
    let mut events = ChainIndexerStream::start(indexer, EVENT_TIMEOUT).await?;
    let ethereum = cluster
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("Ethereum context was not started")?;
    // No request here executes on the EVM, so the target needs no code.
    let target = Address::repeat_byte(0x61);
    let mut argument = [0; 32];
    argument[31] = 6;
    let mut heights = BTreeMap::new();
    let mut observed = Observed::default();
    let mut placed = Vec::new();

    // The placement test's partial successes, beside the shapes below.
    for (name, scenario, nonce) in [
        ("partialSuccess", PlacementScenario::PartialSuccess, 10),
        (
            "fallibleThenFailing",
            PlacementScenario::FallibleThenFailing,
            12,
        ),
    ] {
        let outcome = midnight
            .submit_placement(
                scenario,
                &[
                    (nonce, target.into_array()),
                    (nonce + 1, target.into_array()),
                ],
                argument,
            )
            .await?;
        tracing::info!(name, ?outcome, "review shape submitted");
        anyhow::ensure!(
            outcome.status == "FailFallible" && outcome.committed == outcome.requests[..1],
            "{name}: expected only the first intent to commit: {outcome:?}"
        );
        heights.insert(name.to_string(), outcome.block_height);
        placed.push((
            name,
            request_id(&outcome.requests[0])?,
            request_id(&outcome.requests[1])?,
        ));
    }
    let replay = midnight
        .submit_placement(
            PlacementScenario::RolledBackReplay,
            &[(14, target.into_array())],
            argument,
        )
        .await?;
    tracing::info!(?replay, "review shape submitted");
    anyhow::ensure!(
        replay.status == "FailFallible" && replay.committed == replay.requests,
        "rolledBackReplay: {replay:?}"
    );
    heights.insert("rolledBackReplay".into(), replay.block_height);
    let replay_id = request_id(&replay.requests[0])?;

    // A request filed without a notification, then notified by a call that rolls back.
    let write = midnight
        .submit_adversarial(
            AdversarialScenario::WriteThenRolledBackNotify,
            (15, target.into_array()),
            argument,
        )
        .await?;
    tracing::info!(?write, "review shape submitted");
    anyhow::ensure!(
        write.status == "FailFallible"
            && write.committed
            && write.notifications == [write.request_id.clone()]
            && notification_phase(&write.placement, &write.request_id) == Some("fallible"),
        "writeThenRolledBackNotify: {write:?}"
    );
    heights.insert("writeThenRolledBackNotify".into(), write.block_height);

    // A filing and its rolled-back replay in one transaction.
    let same_tx = midnight
        .submit_adversarial(
            AdversarialScenario::SameTxReplay,
            (16, target.into_array()),
            argument,
        )
        .await?;
    tracing::info!(?same_tx, "review shape submitted");
    anyhow::ensure!(
        same_tx.status == "FailFallible"
            && same_tx.committed
            && same_tx.notifications == [same_tx.request_id.clone(), same_tx.request_id.clone()],
        "sameTxReplay: {same_tx:?}"
    );
    heights.insert("sameTxReplay".into(), same_tx.block_height);

    // SNA-07 against the real vault: a stranger sends a user's flushed deposit in an intent
    // that commits, beside a stale flush that fails.
    let mpc_public_key = format!(
        "0x{}",
        hex::encode(root_public_key.to_encoded_point(false).as_bytes())
    );
    let vault = midnight
        .run_vault_partial_send(
            &mpc_public_key,
            &ethereum.sandbox.external_http_endpoint,
            &ethereum.sandbox.secret_key,
        )
        .await?;
    tracing::info!(?vault, "review shape submitted");
    anyhow::ensure!(
        vault.status == "FailFallible" && vault.committed && vault.retry_rejected,
        "vault partial send: {vault:?}"
    );
    heights.insert("vaultPartialSend".into(), vault.block_height);
    let vault_id = request_id(&vault.request_id)?;

    // A twin: the same request id removed and filed again in one partially successful
    // transaction, after its original was filed and indexed in an earlier block. Its record
    // is in the caller's state at the block and at its parent.
    let original = midnight
        .prepare_twin((0, target.into_array()), argument)
        .await?;
    tracing::info!(?original, "twin original filed");
    let original_id = request_id(&original.request_id)?;
    observed
        .until(&mut events, "the twin original's SignRequest", |observed| {
            observed.indexed().contains(&original_id)
        })
        .await?;
    let indexed_before_twin = observed.indexed().len();
    let twin = midnight
        .fire_twin(
            original_id,
            (0, target.into_array()),
            (1_000, target.into_array()),
            argument,
        )
        .await?;
    tracing::info!(?twin, "review shape submitted");
    anyhow::ensure!(
        twin.status == "FailFallible"
            && twin.committed
            && twin.notifications.len() == 2
            && twin.notifications.contains(&twin.request_id)
            && twin.block_height > original.block_height,
        "twin: {twin:?}"
    );
    heights.insert("twinOriginal".into(), original.block_height);
    heights.insert("twin".into(), twin.block_height);
    // The failing call beside the twin notifies of its own request, which never committed.
    let twin_failing = twin
        .notifications
        .iter()
        .find(|id| **id != twin.request_id)
        .map(|id| request_id(id))
        .context("the twin's failing call did not notify")??;

    let sentinel = midnight
        .submit_is_even(17, target.into_array(), argument, "bool")
        .await?;
    let sentinel_id = request_id(&sentinel.request_id)?;
    observed
        .until(&mut events, "the sentinel SignRequest", |observed| {
            observed.indexed().contains(&sentinel_id)
        })
        .await?;
    let write_id = request_id(&write.request_id)?;
    observed
        .until(
            &mut events,
            "the MPC signatures of the vault deposit and the unnotified filing",
            |observed| {
                observed.responded.contains(&vault_id) && observed.responded.contains(&write_id)
            },
        )
        .await?;
    let count = |id: &[u8; 32]| observed.indexed().iter().filter(|seen| *seen == id).count();
    let mut decisions = serde_json::json!({
        "rolledBackReplay": count(&replay_id),
        "writeThenRolledBackNotify": count(&write_id),
        "sameTxReplay": count(&request_id(&same_tx.request_id)?),
        "vaultPartialSend": count(&vault_id),
        "twinIndexedAfterRefile": observed.indexed()[indexed_before_twin..]
            .iter()
            .filter(|seen| **seen == original_id)
            .count(),
        "twinFailing": count(&twin_failing),
    });
    for (name, committed, rolled_back) in &placed {
        decisions[format!("{name}Committed")] = count(committed).into();
        decisions[format!("{name}RolledBack")] = count(rolled_back).into();
    }
    tracing::info!(%decisions, ?heights, "review decisions");

    // The reader cannot tell which fallible segment committed. A record new in the block was
    // written by a committed segment, so a filing without a notification is signed when a
    // rolled-back call names it, and a record removed and filed again within the block is not.
    anyhow::ensure!(
        decisions
            == serde_json::json!({
                "partialSuccessCommitted": 1,
                "partialSuccessRolledBack": 0,
                "fallibleThenFailingCommitted": 1,
                "fallibleThenFailingRolledBack": 0,
                "rolledBackReplay": 1,
                "writeThenRolledBackNotify": 1,
                "sameTxReplay": 2,
                "vaultPartialSend": 1,
                "twinIndexedAfterRefile": 0,
                "twinFailing": 0,
            }),
        "unexpected reader decisions {decisions}"
    );
    midnight.shutdown().await?;
    Ok(())
}
