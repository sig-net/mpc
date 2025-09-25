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

    pub fn id(&self) -> Participant {
        Participant::from(self.id)
    }

    pub fn info(&self) -> ParticipantInfo {
        ParticipantInfo {
            id: self.id,
            account_id: format!("p{}.test", self.id).parse().unwrap(),
            url: self.server.url(),
            cipher_pk: mpc_keys::hpke::PublicKey::from_bytes(&[0; 32]),
            sign_pk: near_crypto::PublicKey::empty(near_crypto::KeyType::ED25519),
        }
    }

    pub async fn make_offline(&mut self) {
        self.server
            .mock("POST", "/msg")
            .with_status(404)
            .create_async()
            .await;
    }

    pub async fn make_online(&mut self) {
        self.server
            .mock("POST", "/msg")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create_async()
            .await;
    }
}

pub struct MockServers {
    servers: Vec<MockServer>,
}

impl MockServers {
    pub async fn new(nodes: usize) -> Self {
        let mut servers = Self {
            servers: Vec::new(),
        };
        for id in 0..nodes {
            servers.push(id as u32).await;
        }
        servers
    }

    pub fn participants(&self) -> Participants {
        let mut participants = Participants::default();
        for server in &self.servers {
            participants.insert(&server.id(), server.info().clone());
        }
        participants
    }

    pub fn client(&self) -> NodeClient {
        NodeClient::new(&crate::node_client::Options::default())
    }

    pub async fn push(&mut self, id: u32) {
        self.servers.push(MockServer::new(id).await);
    }

    pub async fn push_next(&mut self) -> Participant {
        let id = self.servers.len() as u32;
        self.push(id).await;
        Participant::from(id)
    }

    pub async fn remove(&mut self, id: u32) {
        self.servers.retain(|server| server.id != id);
    }

    pub async fn remove_back(&mut self) {
        self.servers.pop();
    }

    pub async fn swap_remove_front(&mut self) {
        self.servers.swap_remove(0);
    }
}

impl std::ops::Index<usize> for MockServers {
    type Output = MockServer;

    fn index(&self, index: usize) -> &Self::Output {
        &self.servers[index]
    }
}

impl std::ops::IndexMut<usize> for MockServers {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.servers[index]
    }
}
