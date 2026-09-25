use std::time::Duration;

use alloy::primitives::{keccak256, Address, Bytes, U256};
use alloy::providers::ext::AnvilApi as _;
use alloy::providers::{Provider as _, ProviderBuilder};
use anyhow::Context as _;
use integration_tests::cluster;
use mpc_chain_integration_core::utils::test::ChainIndexerStream;
use mpc_chain_integration_core::{MockStateManager, NoopChainTelemetry};
use mpc_chain_midnight::MidnightIndexer;
use mpc_node::sign_bidirectional::{derive_user_address, SignBidirectionalEventExt as _};
use mpc_primitives::{Chain, ChainEvent, SignKind};
use serial_test::serial;
use test_log::test;

const EVENT_TIMEOUT: Duration = Duration::from_secs(8 * 60);
const RETURN_TRUE_RUNTIME_BYTECODE: &str = "600160005260206000f3";

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
    for (nonce, output_type, expected_width, failed) in [
        (0, "bool", 1, false),
        (1, "uint64", 8, false),
        (2, "bytes32", 32, false),
        (3, "uint64", 0, true),
    ] {
        let target = Address::repeat_byte(0x42 + nonce as u8);
        anvil
            .anvil_set_code(
                target,
                Bytes::from(hex::decode(if failed {
                    "60006000fd"
                } else {
                    RETURN_TRUE_RUNTIME_BYTECODE
                })?),
            )
            .await?;

        let mut argument = [0; 32];
        argument[31] = 6;
        midnight
            .submit_is_even(nonce, target.into_array(), argument, output_type)
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
        let mut expected_input = hex::decode("2a2e1320")?;
        expected_input.extend_from_slice(&argument);
        assert_eq!(
            hex::decode(signed.data.trim_start_matches("0x"))?,
            expected_input
        );
        anvil
            .anvil_set_balance(expected_sender, U256::from(10_000_000_000_000_000_000u128))
            .await?;
        let pending = anvil
            .send_raw_transaction(&hex::decode(signed.serialized.trim_start_matches("0x"))?)
            .await?;
        let receipt = pending.get_receipt().await?;
        assert_eq!(receipt.status(), !failed, "unexpected EVM execution status");

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
        let output = midnight.stored_output(request_id).await?;
        assert_eq!(metadata.serialized_output_length, output.len() as u64);
        let signing_metadata = mpc_primitives::AttestationMetadata {
            key_version: sign_event.key_version,
            block_height: metadata.block_height,
            outcome: metadata.outcome,
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
            metadata.outcome,
            if failed {
                mpc_primitives::AttestationOutcomeKind::Failed
            } else {
                mpc_primitives::AttestationOutcomeKind::Executed
            }
        );
        assert_eq!(output.len(), expected_width);
        if failed {
            assert!(output.is_empty());
        }
        midnight
            .settle_response(request_id, &output, failed)
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
        anyhow::Ok(request.id.request_id)
    };
    midnight
        .submit_is_even(4, [0x50; 20], argument, "bool")
        .await?;
    let victim_request = next_sign_request()
        .await
        .context("waiting for the victim's genuine SignRequest")?;
    midnight.notify_as_caller(victim_request).await?;
    midnight
        .submit_is_even(5, [0x51; 20], argument, "bool")
        .await?;
    let after_impersonation = next_sign_request()
        .await
        .context("waiting for the SignRequest after the impersonation")?;
    assert_ne!(
        after_impersonation, victim_request,
        "a notification from a contract other than the named caller was indexed"
    );

    midnight.shutdown().await?;
    Ok(())
}
