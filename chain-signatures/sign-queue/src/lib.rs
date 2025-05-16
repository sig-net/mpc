use deadpool_redis::{Connection, Pool};

use mpc_primitives::{Chain, SignArgs, SignId};
use serde::{Deserialize, Serialize};

/// All relevant info pertaining to an Indexed sign request from an indexer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignRequest {
    pub id: SignId,
    pub args: SignArgs,
    pub chain: Chain,
    pub unix_timestamp: u64,
}

#[derive(Clone)]
pub struct SignQueue {
    redis: Pool,
}

impl SignQueue {
    pub fn new(redis: Pool) -> Self {
        Self { redis }
    }

    async fn connect(&self) -> Option<Connection> {
        self.redis
            .get()
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to connect to redis");
            })
            .ok()
    }

    pub async fn enqueue(&self, data: Vec<u8>) {
        let Some(conn) = self.connect().await else {
            return;
        };
        // let _: () = conn.rpush("sign_queue", data).await?;
    }
}
