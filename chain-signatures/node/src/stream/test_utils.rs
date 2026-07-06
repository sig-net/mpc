//! Shared test fixtures for the `stream` module tests.
//!
//! These helpers encode the *fixture* values (deterministic seeds, well-known
//! test addresses, schema bytes, etc.) that the stream tests repeatedly need.
//! They are compiled only under `cfg(test)` and are re-exported up to the
//! `stream` module so both `stream::tests` and `stream::ops::tests` can reach
//! them via `crate::stream::test_utils`.

use crate::backlog::Backlog;
use crate::mesh::connection::NodeStatus;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::ParticipantInfo;
use crate::rpc::{ContractStateWatcher, RpcAction, RpcChannel};
use crate::stream::run_stream;
use crate::util::current_unix_timestamp;
use alloy::primitives::{Address, B256};
use k256::{AffinePoint, Scalar};
use mockito::Server;
use mpc_chain_canton::CantonChainCtx;
use mpc_chain_integration_core::{ChainStream, NoopChainTelemetry};
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, IndexedSignRequest, RespondBidirectionalEvent,
    SignArgs, SignBidirectionalEvent, SignCommand, SignId, SignKind, Signature,
    SignatureRespondedEvent,
};
use near_primitives::types::AccountId;
use tokio::sync::{mpsc, watch};

pub fn test_indexed_request(
    sign_id: SignId,
    chain: Chain,
    args: SignArgs,
    unix_timestamp_indexed: u64,
    kind: SignKind,
) -> IndexedSignRequest {
    IndexedSignRequest::new(sign_id, args, chain, unix_timestamp_indexed, kind)
}

pub fn test_bidirectional_tx(id: u8, source_chain: Chain, target_chain: Chain) -> BidirectionalTx {
    BidirectionalTx {
        id: BidirectionalTxId(B256::from([id; 32]).0),
        sender: [0u8; 32],
        serialized_transaction: vec![1, 2, 3],
        source_chain,
        target_chain,
        caip2_id: target_chain.caip2_chain_id().to_string(),
        key_version: 1,
        deposit: 1000,
        path: "test_path".to_string(),
        algo: "ECDSA".to_string(),
        dest: "0x1234567890123456789012345678901234567890".to_string(),
        params: "{}".to_string(),
        output_deserialization_schema: vec![],
        respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
        request_id: [id; 32],
        from_address: **Address::ZERO,
        nonce: 0,
    }
}

/// A deterministic `SignArgs` fixture seeded by `id`.
///
/// `..Default::default()` absorbs any fields added to `SignArgs` in the future
/// so this fixture stays forward-compatible without touching every call site.
pub fn test_sign_args(id: u8) -> SignArgs {
    SignArgs {
        entropy: [id; 32],
        epsilon: Scalar::from(1u64),
        payload: Scalar::from(2u64),
        path: "test".to_string(),
        key_version: 1,
    }
}

pub fn test_canton_sign_bidirectional_request(
    sign_id: SignId,
    sign_event_contract_id: &str,
) -> IndexedSignRequest {
    let ctx = CantonChainCtx {
        sign_event_contract_id: sign_event_contract_id.to_string(),
    };
    let chain_ctx =
        Some(borsh::to_vec(&ctx).expect("CantonChainCtx Borsh serialization is infallible"));
    IndexedSignRequest::sign_bidirectional(
        sign_id,
        test_sign_args(sign_id.request_id[0]),
        Chain::Canton,
        current_unix_timestamp(),
        SignBidirectionalEvent {
            sender: [7u8; 32],
            serialized_transaction: vec![1, 2, 3],
            caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
            key_version: 1,
            deposit: 0,
            path: "test_path".to_string(),
            algo: "ECDSA".to_string(),
            dest: "0x1234567890123456789012345678901234567890".to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            chain: Chain::Canton,
            chain_ctx,
        },
    )
}

pub fn respond_event(sign_id: SignId, signature: Signature) -> RespondBidirectionalEvent {
    RespondBidirectionalEvent {
        request_id: sign_id.request_id,
        signature,
        chain: Chain::Solana,
    }
}

pub fn signature_responded_event(
    sign_id: SignId,
    signature: Signature,
    chain: Chain,
) -> SignatureRespondedEvent {
    SignatureRespondedEvent {
        request_id: sign_id.request_id,
        signature,
        chain,
    }
}

/// A minimal `RpcChannel` backed by an `mpsc` channel, for tests that don't
/// need to assert on RPC traffic.
pub fn test_rpc_channel(buffer: usize) -> (RpcChannel, mpsc::Receiver<RpcAction>) {
    let (tx, rx) = mpsc::channel(buffer);
    (RpcChannel { tx }, rx)
}

/// Drive `run_stream` against a two-node mesh backed by in-memory Mockito HTTP
/// servers (one per participant) that always serve an empty checkpoint map.
///
/// This centralizes the ~40 lines of identical setup shared by the Ethereum
/// completion/requeue stream tests: `ContractStateWatcher`, the mock `/checkpoint`
/// endpoints, `MeshState` with two active participants, the `NodeClient`, the
/// `RpcChannel`, and the `run_stream` call itself.
///
/// `servers` are kept alive for the duration of `run_stream` because they are
/// bound to the lifetime of this call, matching the previous inline behavior.
pub async fn run_stream_with_two_node_mesh<S: ChainStream>(
    client: S,
    sign_tx: mpsc::Sender<SignCommand>,
    backlog: Backlog,
    root_pk: AffinePoint,
) {
    let (contract_watcher, _tx) = ContractStateWatcher::with_running(
        &"test.near".parse::<AccountId>().unwrap(),
        root_pk,
        2,
        Default::default(),
    );

    let mut servers = Vec::new();
    for _ in 0..2 {
        let mut server = Server::new_async().await;
        let mut body = Vec::new();
        ciborium::ser::into_writer(
            &std::collections::HashMap::<Chain, crate::backlog::Checkpoint>::new(),
            &mut body,
        )
        .unwrap();
        server
            .mock("GET", "/checkpoint")
            .with_status(200)
            .with_body(body)
            .create_async()
            .await;
        servers.push(server);
    }

    let mut mesh_state = MeshState::default();
    for (index, server) in servers.iter().enumerate() {
        let mut info = ParticipantInfo::new(index as u32);
        info.url = server.url();
        mesh_state.update(
            cait_sith::protocol::Participant::from(index as u32),
            NodeStatus::Active,
            info,
        );
    }
    let (_mesh_state_tx, mesh_state_rx) = watch::channel(mesh_state);
    let (_cp_tx, cp_rx) = watch::channel(None);
    let node_client = NodeClient::new(&Default::default());
    let (rpc, _rpc_rx) = test_rpc_channel(8);

    run_stream(
        client,
        sign_tx,
        rpc,
        backlog,
        NoopChainTelemetry,
        contract_watcher,
        mesh_state_rx,
        node_client,
        cp_rx,
    )
    .await;
}
