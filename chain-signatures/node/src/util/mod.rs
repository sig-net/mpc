use mpc_crypto::{near_public_key_to_affine_point, PublicKey};

use chrono::{DateTime, LocalResult, TimeZone, Utc};
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint};
use tokio::task::{AbortHandle, JoinSet};

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub mod retry;

pub trait NearPublicKeyExt {
    fn into_affine_point(self) -> PublicKey;
}

impl NearPublicKeyExt for String {
    fn into_affine_point(self) -> PublicKey {
        let public_key_value = serde_json::json!(self);
        serde_json::from_value(public_key_value).expect("Failed to deserialize struct")
    }
}

impl NearPublicKeyExt for near_sdk::PublicKey {
    fn into_affine_point(self) -> PublicKey {
        near_public_key_to_affine_point(self)
    }
}

impl NearPublicKeyExt for near_crypto::Secp256K1PublicKey {
    fn into_affine_point(self) -> PublicKey {
        let mut bytes = vec![0x04];
        bytes.extend_from_slice(self.as_ref());
        let point = EncodedPoint::from_bytes(bytes).unwrap();
        PublicKey::from_encoded_point(&point).unwrap()
    }
}

impl NearPublicKeyExt for near_crypto::PublicKey {
    fn into_affine_point(self) -> PublicKey {
        match self {
            near_crypto::PublicKey::SECP256K1(public_key) => public_key.into_affine_point(),
            near_crypto::PublicKey::ED25519(_) => panic!("unsupported key type"),
        }
    }
}

pub trait AffinePointExt {
    fn into_near_public_key(self) -> near_crypto::PublicKey;
    fn to_base58(&self) -> String;
}

impl AffinePointExt for AffinePoint {
    fn into_near_public_key(self) -> near_crypto::PublicKey {
        near_crypto::PublicKey::SECP256K1(
            near_crypto::Secp256K1PublicKey::try_from(
                &self.to_encoded_point(false).as_bytes()[1..65],
            )
            .unwrap(),
        )
    }

    fn to_base58(&self) -> String {
        let key = near_crypto::Secp256K1PublicKey::try_from(
            &self.to_encoded_point(false).as_bytes()[1..65],
        )
        .unwrap();
        format!("{key:?}")
    }
}

pub fn is_elapsed_longer_than_timeout(timestamp_sec: u64, timeout: u64) -> bool {
    if let LocalResult::Single(msg_timestamp) = Utc.timestamp_opt(timestamp_sec as i64, 0) {
        let timeout = Duration::from_millis(timeout);
        let now_datetime: DateTime<Utc> = Utc::now();
        // Calculate the difference in seconds
        let elapsed_duration = now_datetime.signed_duration_since(msg_timestamp);
        let timeout = chrono::Duration::seconds(timeout.as_secs() as i64)
            + chrono::Duration::nanoseconds(timeout.subsec_nanos() as i64);
        elapsed_duration > timeout
    } else {
        false
    }
}

pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

/// Encode `(string, bytes, string, uint256, string, string, string, string)`
/// exactly like the legacy `ethabi` path so request IDs stay stable.
#[allow(clippy::too_many_arguments)]
pub fn ethabi_request_id(
    sender: String,
    payload: [u8; 32],
    path: String,
    key_version: u32,
    chain_id: String,
    algo: String,
    dest: String,
    params: String,
) -> [u8; 32] {
    const HEAD_WORDS: usize = 8;
    const WORD_SIZE: usize = 32;

    fn u256_word(value: u64) -> [u8; WORD_SIZE] {
        let mut word = [0u8; WORD_SIZE];
        word[WORD_SIZE - 8..].copy_from_slice(&value.to_be_bytes());
        word
    }

    fn push_dynamic(
        heads: &mut Vec<[u8; WORD_SIZE]>,
        tails: &mut Vec<u8>,
        head_size: usize,
        bytes: &[u8],
    ) {
        let offset = head_size + tails.len();
        heads.push(u256_word(offset as u64));
        tails.extend_from_slice(&u256_word(bytes.len() as u64));
        tails.extend_from_slice(bytes);

        let padding = (WORD_SIZE - (bytes.len() % WORD_SIZE)) % WORD_SIZE;
        tails.extend(std::iter::repeat_n(0u8, padding));
    }

    let head_size = HEAD_WORDS * WORD_SIZE;
    let mut heads = Vec::with_capacity(HEAD_WORDS);
    let mut tails = Vec::new();

    push_dynamic(&mut heads, &mut tails, head_size, sender.as_bytes());
    push_dynamic(&mut heads, &mut tails, head_size, payload.as_slice());
    push_dynamic(&mut heads, &mut tails, head_size, path.as_bytes());
    heads.push(u256_word(key_version as u64));
    push_dynamic(&mut heads, &mut tails, head_size, chain_id.as_bytes());
    push_dynamic(&mut heads, &mut tails, head_size, algo.as_bytes());
    push_dynamic(&mut heads, &mut tails, head_size, dest.as_bytes());
    push_dynamic(&mut heads, &mut tails, head_size, params.as_bytes());

    let mut encoded = Vec::with_capacity(head_size + tails.len());
    for head in heads {
        encoded.extend_from_slice(&head);
    }
    encoded.extend_from_slice(&tails);

    *alloy::primitives::keccak256(encoded)
}

/// Calculate elapsed time from a unix timestamp to now
pub fn unix_elapsed(unix_timestamp: u64) -> Duration {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Duration::from_secs(now.saturating_sub(unix_timestamp))
}

pub const fn first_8_bytes(input: [u8; 32]) -> [u8; 8] {
    let mut output = [0u8; 8];
    let mut i = 0;
    while i < 8 {
        output[i] = input[i];
        i += 1;
    }
    output
}

pub struct JoinMap<T, U> {
    mapping: HashMap<T, AbortHandle>,
    mapping_id: HashMap<tokio::task::Id, T>,
    tasks: JoinSet<U>,
}

impl<T, U> Default for JoinMap<T, U> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, U> JoinMap<T, U> {
    pub fn new() -> Self {
        Self {
            mapping: HashMap::new(),
            mapping_id: HashMap::new(),
            tasks: JoinSet::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.mapping.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mapping.is_empty()
    }
}

impl<T, U> JoinMap<T, U>
where
    T: Copy + Hash + Eq,
    U: Send + 'static,
{
    pub fn contains_key(&self, key: &T) -> bool {
        self.mapping.contains_key(key)
    }

    pub fn spawn(&mut self, key: T, task: impl Future<Output = U> + Send + 'static) {
        let handle = self.tasks.spawn(task);
        let task_id = handle.id();
        self.mapping.insert(key, handle);
        self.mapping_id.insert(task_id, key);
    }

    pub fn abort(&mut self, key: T) -> bool {
        if let Some(handle) = self.mapping.remove(&key) {
            handle.abort();

            if let Some(task_id) = self
                .mapping_id
                .iter()
                .find_map(|(id, mapped_key)| (*mapped_key == key).then_some(*id))
            {
                self.mapping_id.remove(&task_id);
            }

            true
        } else {
            false
        }
    }

    pub async fn join_next(&mut self) -> Option<Result<(T, U), T>> {
        let outcome = self.tasks.join_next_with_id().await?;
        let (id, outcome) = match outcome {
            Ok((id, outcome)) => (id, Some(outcome)),
            Err(err) => (err.id(), None),
        };

        let key = self.mapping_id.remove(&id)?;
        self.mapping.remove(&key);
        match outcome {
            Some(outcome) => Some(Ok((key, outcome))),
            None => Some(Err(key)),
        }
    }
}

impl<T, U> Drop for JoinMap<T, U> {
    fn drop(&mut self) {
        for handle in self.mapping.values() {
            handle.abort();
        }
    }
}

/// Tracks the remaining time budget for a signature attempt.
/// When the budget is exhausted, the attempt fails and we reorganize.
pub struct TimeoutBudget {
    started: Instant,
    timeout: Duration,
}

impl TimeoutBudget {
    pub fn new(timeout: Duration) -> Self {
        Self {
            started: Instant::now(),
            timeout,
        }
    }

    /// Returns the remaining time in the budget, or Duration::ZERO if exhausted.
    pub fn remaining(&self) -> Duration {
        self.timeout.saturating_sub(self.started.elapsed())
    }

    /// Returns true if the budget is exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.started.elapsed() >= self.timeout
    }

    /// Resets the budget with a new timeout (used when starting a new attempt).
    pub fn reset(&mut self, timeout: Duration) {
        self.started = Instant::now();
        self.timeout = timeout;
    }
}

pub fn channel_len(tx: &tokio::sync::mpsc::Sender<impl Sized>) -> usize {
    tx.max_capacity() - tx.capacity()
}
