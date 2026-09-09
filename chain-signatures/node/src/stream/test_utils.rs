//! Shared test fixtures for the `stream` module tests.

use crate::backlog::Backlog;
use crate::mesh::connection::NodeStatus;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::ParticipantInfo;
use crate::rpc::{ContractStateWatcher, RpcAction, RpcChannel};
use crate::stream::{supervisor::run_supervised, StreamContext};
use crate::types::SignCommand;

use alloy::primitives::{Address, B256};
use cait_sith::protocol::Participant;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use mockito::Server;
use mpc_chain_canton::CantonChainCtx;
use mpc_chain_integration_core::{ChainIndexer, NoopChainTelemetry};
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, CheckpointDigest, IndexedSignRequest,
    RespondBidirectionalEvent, SignArgs, SignBidirectionalEvent, SignId, SignKind, Signature,
    SignatureRespondedEvent,
};
use mpc_utils::time::current_unix_timestamp;
use near_primitives::types::AccountId;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};

pub fn test_indexed_request(
    sign_id: SignId,
    chain: Chain,
    args: SignArgs,
    unix_timestamp_indexed: u64,
    kind: SignKind,
) -> Arc<IndexedSignRequest> {
    Arc::new(IndexedSignRequest::new(
        sign_id,
        args,
        chain,
        unix_timestamp_indexed,
        kind,
    ))
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
) -> Arc<IndexedSignRequest> {
    let ctx = CantonChainCtx {
        sign_event_contract_id: sign_event_contract_id.to_string(),
    };
    let chain_ctx =
        Some(borsh::to_vec(&ctx).expect("CantonChainCtx Borsh serialization is infallible"));
    Arc::new(IndexedSignRequest::sign_bidirectional(
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
    ))
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

pub fn test_rpc_channel(buffer: usize) -> (RpcChannel, mpsc::Receiver<RpcAction>) {
    let (tx, rx) = mpsc::channel(buffer);
    (RpcChannel { tx }, rx)
}

/// Build a test [`StreamContext`] and return the checkpoint / mesh watch
/// senders so callers can drive them. `threshold` is the contract-watcher's
/// signing threshold.
pub fn make_test_stream_context(
    backlog: Backlog,
    sign_tx: mpsc::Sender<SignCommand>,
    caught_up: bool,
    root_pk: AffinePoint,
    threshold: usize,
) -> (
    StreamContext,
    watch::Sender<Option<CheckpointDigest>>,
    watch::Sender<MeshState>,
    mpsc::Receiver<RpcAction>,
) {
    let account_id: AccountId = "test.near".parse().unwrap();
    let (contract_watcher, _tx) =
        ContractStateWatcher::with_running(&account_id, root_pk, threshold, Default::default());
    let (mesh_tx, mesh_rx) = watch::channel(MeshState::default());
    let (cp_tx, cp_rx) = watch::channel(None);
    let node_client = NodeClient::new(&Default::default());
    let (rpc, rpc_rx) = test_rpc_channel(8);
    let mut ctx = StreamContext::new(
        backlog,
        sign_tx,
        rpc,
        contract_watcher,
        mesh_rx,
        node_client,
        cp_rx,
    );
    ctx.caught_up = caught_up;
    (ctx, cp_tx, mesh_tx, rpc_rx)
}

pub fn make_test_stream_context_with_rpc(
    backlog: Backlog,
    sign_tx: mpsc::Sender<SignCommand>,
    caught_up: bool,
    root_pk: AffinePoint,
) -> (StreamContext, mpsc::Receiver<RpcAction>) {
    let account_id: AccountId = "test.near".parse().unwrap();
    let (contract_watcher, _tx) =
        ContractStateWatcher::with_running(&account_id, root_pk, 1, Default::default());
    let (_mesh_tx, mesh_rx) = watch::channel(MeshState::default());
    let (_cp_tx, cp_rx) = watch::channel(None);
    let node_client = NodeClient::new(&Default::default());
    let (rpc, rpc_rx) = test_rpc_channel(8);
    let mut ctx = StreamContext::new(
        backlog,
        sign_tx,
        rpc,
        contract_watcher,
        mesh_rx,
        node_client,
        cp_rx,
    );
    ctx.caught_up = caught_up;
    (ctx, rpc_rx)
}

/// Convenience wrapper for tests that don't need the watch senders and use the
/// generator as the root public key at signing threshold `1`.
pub fn make_test_stream_context_with_generator_pk(
    backlog: Backlog,
    sign_tx: mpsc::Sender<SignCommand>,
    caught_up: bool,
) -> StreamContext {
    let (ctx, _, _, _) = make_test_stream_context(
        backlog,
        sign_tx,
        caught_up,
        ProjectivePoint::GENERATOR.to_affine(),
        1,
    );
    ctx
}

/// Drive `run_supervised` against a two-node mesh backed by in-memory Mockito HTTP
/// servers (one per participant) that always serve an empty checkpoint map.
pub async fn run_stream_with_two_node_mesh<I: ChainIndexer>(
    indexer: I,
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
        mesh_state.update(Participant::from(index as u32), NodeStatus::Active, info);
    }
    let (_mesh_state_tx, mesh_state_rx) = watch::channel(mesh_state);
    let (_cp_tx, cp_rx) = watch::channel(None);
    let node_client = NodeClient::new(&Default::default());
    let (rpc, _rpc_rx) = test_rpc_channel(8);

    run_supervised(
        indexer,
        StreamContext::new(
            backlog,
            sign_tx,
            rpc,
            contract_watcher,
            mesh_state_rx,
            node_client,
            cp_rx,
        ),
        NoopChainTelemetry,
    )
    .await;
}
