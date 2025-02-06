//! A FIFO queue for signature requests between many chain indexers (producers)
//! and one MPC node (consumer).
//!
//! Under the "sign_request_queue" key on redis, we store signature requests
//! that have been validated by a chain indexer. The MPC node is picking them up
//! as the sole consumer on the queue.
//!
//! The redis type is a list, therefore, use `lpush` and `brpop` to modify the
//! queue.

use crate::protocol::SignRequest;
use redis::AsyncCommands;

const QUEUE_KEY: &str = "sign_request_queue";

/// Take a validated sign request from a chain and hand it off to the MPC node
/// for processing.
pub async fn push_sign_request(
    redis_pool: &deadpool_redis::Pool,
    request: SignRequest,
) -> anyhow::Result<()> {
    let mut request_cbor = Vec::new();
    ciborium::ser::into_writer(&request, &mut request_cbor)?;

    let mut conn = redis_pool.get().await?;
    // Using a redis list as a FIFO queue, pushing on the left and popping on the right.
    let _len: usize = conn.lpush(QUEUE_KEY, request_cbor).await?;

    Ok(())
}

/// Take a signature request from the head of the FIFO queue.
///
/// Blocks until a request is available, asynchronously waiting for a
/// notification by redis.
pub async fn pop_sign_request(redis_pool: &deadpool_redis::Pool) -> anyhow::Result<SignRequest> {
    let mut conn = redis_pool.get().await?;
    // Using a redis list as a FIFO queue, pushing on the left and popping on the right.
    // timeout = 0.0 will block indefinitely
    let maybe_request_cbor: Option<Vec<u8>> = conn.brpop(QUEUE_KEY, 0.0).await?;

    if let Some(request_cbor) = maybe_request_cbor {
        let cursor = std::io::Cursor::new(request_cbor);

        let request = ciborium::de::from_reader(cursor)?;
        Ok(request)
    } else {
        // this is against the redis documentation
        // https://redis.io/docs/latest/commands/blpop/
        anyhow::bail!("redis BRPOP with timeout=0.0 returned nil value");
    }
}
