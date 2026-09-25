use std::time::Duration;

use alloy::primitives::{keccak256, Address, Bytes, U256};
use alloy::providers::ext::AnvilApi as _;
use alloy::providers::{Provider as _, ProviderBuilder};
use alloy::rpc::types::{TransactionInput, TransactionRequest};
use anyhow::Context as _;
use integration_tests::cluster;
use mpc_chain_integration_core::utils::test::ChainIndexerStream;
use mpc_chain_integration_core::{MockStateManager, NoopChainTelemetry};
use mpc_chain_midnight::MidnightIndexer;
use mpc_node::sign_bidirectional::{derive_user_address, SignBidirectionalEventExt as _};
use mpc_primitives::{Chain, ChainEvent, SignKind};
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
        midnight
            .submit_is_even_with_schemas(
                nonce as u64,
                target.into_array(),
                case.argument,
                &case.output_schema,
                &case.response_schema,
            )
            .await?;
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
            if failed {
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
        assert_eq!(metadata.outcome, outcome);
        assert_eq!(metadata.serialized_output_length, output.len() as u64);
        assert_eq!(
            metadata.digest,
            mpc_compact_hashing::compute_attestation_hash(
                &response.request_id,
                &mpc_primitives::AttestationMetadata {
                    key_version: sign_event.key_version,
                    block_height: replacement_height,
                    outcome,
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
