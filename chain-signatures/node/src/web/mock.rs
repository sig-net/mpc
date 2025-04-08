use cait_sith::protocol::Participant;
use mockito::ServerGuard;

use crate::{
    node_client::NodeClient,
    protocol::{contract::primitives::Participants, ParticipantInfo},
};

use super::StateView;

pub struct MockServer {
    id: u32,
    server: ServerGuard,
}

impl MockServer {
    async fn new(id: u32) -> Self {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/state")
            .with_status(201)
            .with_header("content-type", "text/plain")
            .with_body(
                serde_json::to_vec(&StateView::Running {
                    participants: vec![Participant::from(0)],
                    triple_count: 0,
                    triple_mine_count: 0,
                    triple_potential_count: 0,
                    presignature_count: 0,
                    presignature_mine_count: 0,
                    presignature_potential_count: 0,
                    latest_block_height: 0,
                    is_stable: true,
                })
                .unwrap(),
            )
            .create_async()
            .await;

        server
            .mock("POST", "/msg")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create_async()
            .await;

        Self { id, server }
    }

    fn info(&self) -> ParticipantInfo {
        ParticipantInfo {
            id: self.id,
            account_id: format!("p{}.test", self.id).parse().unwrap(),
            url: self.server.url(),
            cipher_pk: mpc_keys::hpke::PublicKey::from_bytes(&[0; 32]),
            sign_pk: near_crypto::PublicKey::empty(near_crypto::KeyType::ED25519),
        }
    }
}

pub struct MockServers {
    servers: Vec<MockServer>,
}

impl MockServers {
    pub async fn new(num_nodes: u32) -> Self {
        let mut servers = Vec::new();
        for i in 0..num_nodes {
            servers.push(MockServer::new(i).await);
        }
        Self { servers }
    }

    pub fn participants(&self) -> Participants {
        let mut participants = Participants::default();
        for server in &self.servers {
            participants.insert(&Participant::from(server.id), server.info().clone());
        }
        participants
    }

    pub fn client(&self) -> NodeClient {
        NodeClient::new(&crate::node_client::Options::default())
    }
}
