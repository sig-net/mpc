use crate::backlog::Backlog;
use crate::indexer_common::{process_respond_bidirectional_event, process_respond_event};
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::IndexedSignRequest;
use crate::protocol::{Chain, Sign};
use crate::rpc::ContractStateWatcher;
use async_trait::async_trait;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::watch;

/// Unified event produced by a chain client
pub enum ChainEvent {
    SignRequest(IndexedSignRequest),
    Respond(crate::indexer_common::SignatureRespondedEvent),
    RespondBidirectional(crate::indexer_common::RespondBidirectionalEvent),
}

impl std::fmt::Debug for ChainEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainEvent::SignRequest(r) => f.debug_tuple("SignRequest").field(&r.id).finish(),
            ChainEvent::Respond(_) => write!(f, "Respond(...)"),
            ChainEvent::RespondBidirectional(_) => write!(f, "RespondBidirectional(...)"),
        }
    }
}

#[async_trait]
pub trait ChainClient: Send + 'static {
    const CHAIN: Chain;
    async fn next_event(&mut self) -> Option<ChainEvent>;
}

/// Shared indexer loop: recovers backlog then processes events from the client
pub async fn run_indexer<C: ChainClient>(
    mut client: C,
    sign_tx: mpsc::Sender<Sign>,
    backlog: Backlog,
    mut contract_watcher: ContractStateWatcher,
    mut mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
    total_timeout: Duration,
) {
    let chain = C::CHAIN;

    tracing::info!(%chain, "starting indexer loop");

    crate::indexer_common::recover_backlog(
        &backlog,
        &mut contract_watcher,
        &mut mesh_state,
        &node_client,
        chain,
        sign_tx.clone(),
        total_timeout,
    )
    .await;

    while let Some(event) = client.next_event().await {
        match event {
            ChainEvent::SignRequest(req) => {
                // process sign request (insert into backlog + send sign request)
                if let Err(err) = crate::indexer_common::process_sign_request(
                    req,
                    sign_tx.clone(),
                    backlog.clone(),
                )
                .await
                {
                    tracing::error!(?err, chain = %chain, "failed to process sign request");
                }
            }
            ChainEvent::Respond(ev) => {
                if let Err(err) =
                    process_respond_event(ev, sign_tx.clone(), &mut contract_watcher, &backlog)
                        .await
                {
                    tracing::error!(?err, chain = %chain, "failed to process respond event");
                }
            }
            ChainEvent::RespondBidirectional(ev) => {
                if let Err(err) =
                    process_respond_bidirectional_event(ev, sign_tx.clone(), &backlog).await
                {
                    tracing::error!(?err, chain = %chain, "failed to process respond bidirectional event");
                }
            }
        }
    }

    tracing::warn!(%chain, "indexer shut down");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::Backlog;
    use crate::mesh::MeshState;
    use crate::node_client::NodeClient;
    use crate::protocol::Chain;
    use crate::protocol::IndexedSignRequest;
    use crate::protocol::Sign;
    use crate::protocol::SignRequestType;
    use crate::rpc::ContractStateWatcher;
    use crate::util::current_unix_timestamp;
    use k256::Scalar;
    use mpc_primitives::SignArgs;
    use mpc_primitives::SignId;
    use near_primitives::types::AccountId;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    struct MockClient {
        events: Vec<Option<ChainEvent>>,
    }

    #[async_trait::async_trait]
    impl ChainClient for MockClient {
        const CHAIN: Chain = Chain::Solana;
        async fn next_event(&mut self) -> Option<ChainEvent> {
            if self.events.is_empty() {
                return None;
            }
            self.events.remove(0)
        }
    }

    #[tokio::test]
    async fn run_indexer_handles_sign_and_respond() {
        let backlog = Backlog::new();
        let sign_id = SignId::new([1u8; 32]);

        // construct an IndexedSignRequest
        let args = SignArgs {
            entropy: [0u8; 32],
            epsilon: Scalar::from(1u64),
            payload: Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        };

        let indexed = IndexedSignRequest {
            id: sign_id,
            args: args.clone(),
            chain: Chain::Solana,
            timestamp_created: std::time::Instant::now(),
            unix_timestamp_indexed: current_unix_timestamp(),
            total_timeout: Duration::from_secs(5),
            sign_request_type: SignRequestType::Sign,
        };

        // Prepare a respond event that matches the sign id
        let sig_responded = crate::indexer_common::SignatureRespondedEvent::Solana(
            signet_program::SignatureRespondedEvent {
                request_id: sign_id.request_id,
                responder: solana_sdk::pubkey::Pubkey::new_unique(),
                signature: signet_program::Signature {
                    big_r: signet_program::AffinePoint {
                        x: [0u8; 32],
                        y: [0u8; 32],
                    },
                    s: [0u8; 32],
                    recovery_id: 0,
                },
            },
        );

        let mut client = MockClient {
            events: vec![
                Some(ChainEvent::SignRequest(indexed.clone())),
                Some(ChainEvent::Respond(sig_responded)),
                None,
            ],
        };

        let (sign_tx, mut sign_rx) = mpsc::channel(4);

        let (mut contract_watcher, _tx) = ContractStateWatcher::with_running(
            &"test.near".parse::<AccountId>().unwrap(),
            k256::ProjectivePoint::GENERATOR.to_affine(),
            0,
            Default::default(),
        );
        let (mesh_state_tx, mesh_state_rx) = tokio::sync::watch::channel(MeshState::default());
        let node_client = NodeClient::new(&Default::default());

        // Run the indexer
        run_indexer(
            client,
            sign_tx.clone(),
            backlog.clone(),
            contract_watcher,
            mesh_state_rx,
            node_client,
            Duration::from_secs(5),
        )
        .await;

        // We should have received the Request then Completion
        let msg1 = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match msg1 {
            Sign::Request(req) => assert_eq!(req.id, sign_id),
            _ => panic!("expected request"),
        }

        let msg2 = timeout(Duration::from_secs(1), sign_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match msg2 {
            Sign::Completion(id) => assert_eq!(id, sign_id),
            _ => panic!("expected completion"),
        }
    }
}
