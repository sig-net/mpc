use mpc_crypto::{near_public_key_to_affine_point, PublicKey};

use chrono::{DateTime, LocalResult, TimeZone, Utc};
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint};
use tokio::task::{AbortHandle, JoinSet};

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        format!("{:?}", key)
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

pub fn duration_between_unix(from_timestamp: u64, to_timestamp: u64) -> Duration {
    Duration::from_secs(to_timestamp - from_timestamp)
}

pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
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
}

impl<T, U> JoinMap<T, U>
where
    T: Copy + Hash + Eq,
    U: Send + 'static,
{
    pub fn len(&self) -> usize {
        self.mapping.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mapping.is_empty()
    }

    pub fn contains_key(&self, key: &T) -> bool {
        self.mapping.contains_key(key)
    }

    pub fn spawn(&mut self, key: T, task: impl Future<Output = U> + Send + 'static) {
        let handle = self.tasks.spawn(task);
        let task_id = handle.id();
        self.mapping.insert(key, handle);
        self.mapping_id.insert(task_id, key);
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
