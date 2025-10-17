use cait_sith::protocol::Participant;
use mockito::ServerGuard;
use near_sdk::AccountId;

use crate::{
    node_client::NodeClient,
    protocol::{contract::primitives::Participants, state::NodeStatus, ParticipantInfo},
};

use super::StateView;

pub struct MockServer {
    id: u32,
    node_id: AccountId,
    server: ServerGuard,
}

impl MockServer {
    async fn run(id: u32) -> Self {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/state")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(default_state_body())
            .create_async()
            .await;

        server
            .mock("GET", "/status")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(default_status_body(id))
            .create_async()
            .await;

        server
            .mock("POST", "/msg")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create_async()
            .await;

        let node_id = format!("p{id}.test").parse().unwrap();
        Self {
            id,
            node_id,
            server,
        }
    }

    pub fn id(&self) -> Participant {
        Participant::from(self.id)
    }

    pub fn info(&self) -> ParticipantInfo {
        ParticipantInfo {
            id: self.id,
            account_id: self.node_id.clone(),
            url: self.server.url(),
            cipher_pk: mpc_keys::hpke::PublicKey::from_bytes(&[0; 32]),
            sign_pk: near_crypto::PublicKey::empty(near_crypto::KeyType::ED25519),
        }
    }

    pub fn account_id(&self) -> &AccountId {
        &self.node_id
    }

    pub async fn make_offline(&mut self) {
        self.server
            .mock("GET", "/status")
            .with_status(404)
            .create_async()
            .await;
    }

    pub async fn make_online(&mut self) {
        self.server
            .mock("GET", "/status")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(default_status_body(self.id))
            .create_async()
            .await;
    }
}

pub struct MockServers {
    servers: Vec<MockServer>,
}

impl MockServers {
    pub async fn run(nodes: usize) -> Self {
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
        self.servers.push(MockServer::run(id).await);
    }

    pub async fn push_next(&mut self) -> Participant {
        let id = self.servers.len() as u32;
        self.push(id).await;
        Participant::from(id)
    }

    pub fn remove(&mut self, id: u32) {
        self.servers.retain(|server| server.id != id);
    }

    pub fn remove_back(&mut self) {
        self.servers.pop();
    }

    pub fn swap_remove_front(&mut self) {
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

fn default_state_body() -> Vec<u8> {
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
    .unwrap()
}

fn default_status_body(id: u32) -> Vec<u8> {
    serde_json::to_vec(&NodeStatus::Running {
        me: Participant::from(id),
        participants: vec![Participant::from(0)],
        ongoing_triple_gen: 0,
        ongoing_presignature_gen: 0,
    })
    .unwrap()
}
