pub mod app_data_storage;
pub mod presignature_storage;
pub mod secret_storage;
pub mod triple_storage;

pub use presignature_storage::PresignatureStorage;
pub use triple_storage::TripleStorage;

use crate::protocol::presignature::{Presignature, PresignatureId};
use crate::protocol::triple::{Triple, TripleId};
use presignature_storage::PresignatureSlot;
use triple_storage::TripleSlot;

use cait_sith::protocol::Participant;
use deadpool_redis::{Connection, Pool};
use near_sdk::AccountId;
use redis::{AsyncCommands as _, FromRedisValue, ToRedisArgs};

use std::collections::HashMap;
use std::fmt;

// Can be used to "clear" redis storage in case of a breaking change
pub const STORAGE_VERSION: &str = "v8";

/// Configures storage.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "storage_options")]
pub struct Options {
    /// env used to differentiate among environments.
    #[clap(long, env("MPC_ENV"))]
    pub env: String,
    /// GCP project ID.
    #[clap(long, env("MPC_GCP_PROJECT_ID"))]
    pub gcp_project_id: String,
    /// GCP Secret Manager ID that will be used to load/store the node's secret key share.
    #[clap(long, env("MPC_SK_SHARE_SECRET_ID"), requires_all=["gcp_project_id"])]
    pub sk_share_secret_id: Option<String>,
    /// Mostly for integration tests.
    #[arg(long, env("MPC_SK_SHARE_LOCAL_PATH"))]
    pub sk_share_local_path: Option<String>,
    #[arg(long, env("MPC_REDIS_URL"))]
    pub redis_url: String,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        let mut opts = vec![
            "--env".to_string(),
            self.env,
            "--gcp-project-id".to_string(),
            self.gcp_project_id,
        ];
        if let Some(sk_share_secret_id) = self.sk_share_secret_id {
            opts.extend(vec!["--sk-share-secret-id".to_string(), sk_share_secret_id]);
        }
        if let Some(sk_share_local_path) = self.sk_share_local_path {
            opts.extend(vec![
                "--sk-share-local-path".to_string(),
                sk_share_local_path,
            ]);
        }

        opts
    }
}

pub trait PersistentProtocol: Sized {
    type Id: Copy + fmt::Display + fmt::Debug + Send + Sync + tracing::Value + ToRedisArgs;
    type Slot;

    fn id(&self) -> Self::Id;
    fn participants(&self) -> &[Participant];
    fn new_slot(id: Self::Id, storage: &ProtocolStorage<Self>) -> Self::Slot;
}

impl PersistentProtocol for Triple {
    type Id = TripleId;
    type Slot = TripleSlot;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn participants(&self) -> &[Participant] {
        &self.public.participants
    }

    fn new_slot(id: Self::Id, storage: &ProtocolStorage<Self>) -> Self::Slot {
        TripleSlot::new(id, storage.clone())
    }
}

impl PersistentProtocol for Presignature {
    type Id = PresignatureId;
    type Slot = PresignatureSlot;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn participants(&self) -> &[Participant] {
        &self.participants
    }

    fn new_slot(id: Self::Id, storage: &ProtocolStorage<Self>) -> Self::Slot {
        PresignatureSlot::new(id, storage.clone())
    }
}

pub struct ProtocolStorage<T> {
    redis: Pool,
    name: String,
    protocol_key: String,
    used_key: String,
    reserved_key: String,
    owner_keys: String,
    participant_keys: String,

    phantom: std::marker::PhantomData<T>,
}

impl<T> Clone for ProtocolStorage<T> {
    fn clone(&self) -> Self {
        Self {
            redis: self.redis.clone(),
            name: self.name.clone(),
            protocol_key: self.protocol_key.clone(),
            used_key: self.used_key.clone(),
            reserved_key: self.reserved_key.clone(),
            owner_keys: self.owner_keys.clone(),
            participant_keys: self.participant_keys.clone(),

            phantom: std::marker::PhantomData,
        }
    }
}

impl<T> ProtocolStorage<T>
where
    T: PersistentProtocol + ToRedisArgs,
{
    fn init(name: &str, redis: Pool, account_id: &AccountId) -> Self {
        Self {
            redis,
            name: name.into(),
            protocol_key: format!("{name}:{STORAGE_VERSION}:{account_id}"),
            used_key: format!("{name}_used:{STORAGE_VERSION}:{account_id}"),
            reserved_key: format!("{name}_reserved:{STORAGE_VERSION}:{account_id}"),
            owner_keys: format!("{name}_owners:{STORAGE_VERSION}:{account_id}"),
            participant_keys: format!("{name}_participants:{STORAGE_VERSION}:{account_id}"),

            phantom: std::marker::PhantomData,
        }
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

    pub async fn fetch_owned<R: FromRedisValue + Default>(&self, me: Participant) -> R {
        let Some(mut conn) = self.connect().await else {
            return R::default();
        };

        conn.sunion((&self.reserved_key, self.owner_key(me)))
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to fetch (mine | reserved) {}", self.name);
            })
            .unwrap_or_default()
    }

    pub async fn fetch_participants(&self, id: T::Id) -> Vec<Participant> {
        let Some(mut conn) = self.connect().await else {
            return Vec::new();
        };
        conn.smembers(self.participant_key(id))
            .await
            .inspect_err(|err| {
                tracing::warn!(id, ?err, "failed to fetch participants for {}", self.name);
            })
            .map(|v: Vec<u32>| v.into_iter().map(Participant::from).collect::<Vec<_>>())
            .unwrap_or_default()
    }

    pub async fn contains(&self, id: T::Id) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.hexists(&self.protocol_key, id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if {} is stored", self.name);
                false
            }
        }
    }

    pub async fn contains_by_owner(&self, id: T::Id, owner: Participant) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };

        match conn.sismember(self.owner_key(owner), id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if {} is owned by us", self.name);
                false
            }
        }
    }

    pub async fn contains_used(&self, id: T::Id) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.hexists(&self.used_key, id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if {} in used set", self.name);
                false
            }
        }
    }

    pub async fn contains_reserved(&self, id: T::Id) -> bool {
        let Some(mut conn) = self.connect().await else {
            return false;
        };
        match conn.sismember(&self.reserved_key, id).await {
            Ok(exists) => exists,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to check if {} in reserved set", self.name);
                false
            }
        }
    }

    /// Get the number of unspent protocols that were generated by this node.
    pub async fn len_generated(&self) -> usize {
        let Some(mut conn) = self.connect().await else {
            return 0;
        };
        conn.hlen(&self.protocol_key)
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to get length of generated {}s", self.name);
            })
            .unwrap_or(0)
    }

    /// Get the number of unspent protocols by a specific owner.
    pub async fn len_by_owner(&self, owner: Participant) -> usize {
        let Some(mut conn) = self.connect().await else {
            return 0;
        };
        conn.scard(self.owner_key(owner))
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to get length of {}s", self.name);
            })
            .unwrap_or(0)
    }

    /// Checks if the storage is empty.
    pub async fn is_empty(&self) -> bool {
        self.len_generated().await == 0
    }

    pub async fn reserve(&self, id: T::Id) -> Option<T::Slot> {
        const SCRIPT: &str = r#"
            local protocol_key = KEYS[1]
            local used_key = KEYS[2]
            local reserved_key = KEYS[3]
            local name = KEYS[4]
            local protocol_id = ARGV[1]

            -- cannot reserve this protocol if it already exists.
            if redis.call("SADD", reserved_key, protocol_id) == 0 then
                return {err = "WARN " .. name .. " " .. protocol_id .. " has already been reserved"}
            end

            -- cannot reserve this protocol if its already in storage.
            if redis.call("HEXISTS", protocol_key, protocol_id) == 1 then
                return {err = "WARN " .. name .. " " .. protocol_id .. " has already been stored"}
            end

            -- cannot reserve this protocol if it has already been used.
            if redis.call("HEXISTS", used_key, protocol_id) == 1 then
                return {err = "WARN " .. name .. " " .. protocol_id .. " has already been used"}
            end
        "#;

        let mut conn = self.connect().await?;
        let result: Result<(), _> = redis::Script::new(SCRIPT)
            .key(&self.protocol_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .key(&self.name)
            .arg(id)
            .invoke_async(&mut conn)
            .await;

        match result {
            Ok(_) => Some(T::new_slot(id, self)),
            Err(err) => {
                tracing::warn!(?err, "failed to reserve {}", self.name);
                None
            }
        }
    }

    async fn unreserve<const N: usize>(&self, protocols: [T::Id; N]) {
        let Some(mut conn) = self.connect().await else {
            return;
        };
        let outcome: Result<(), _> = conn.srem(&self.reserved_key, &protocols).await;
        if let Err(err) = outcome {
            tracing::warn!(?protocols, ?err, "failed to unreserve {}s", self.name);
        }
    }

    /// Kicks participants from the given protocols.
    pub async fn kick_participants(&self, kick: HashMap<T::Id, Vec<Participant>>) {
        if kick.is_empty() {
            return;
        }
        let Some(mut conn) = self.connect().await else {
            return;
        };
        let mut pipe = redis::pipe();
        pipe.atomic();
        for (id, participants) in kick {
            pipe.srem(
                self.participant_key(id),
                participants
                    .into_iter()
                    .map(|p| Into::<u32>::into(p).to_string())
                    .collect::<Vec<_>>(),
            );
        }

        let outcome: Result<(), _> = pipe.query_async(&mut conn).await;
        if let Err(err) = outcome {
            tracing::warn!(?err, "failed to kick participants from {}", self.name);
        }
    }

    pub async fn remove_outdated<'a, R: FromRedisValue + Default>(
        &'a self,
        owner: Participant,
        owner_shares: impl IntoIterator<Item = &'a T::Id>,
    ) -> R {
        const SCRIPT: &str = r#"
            local protocol_key = KEYS[1]
            local reserved_key = KEYS[2]
            local owner_key = KEYS[3]

            -- convert the list of ids to a table for easy lookup
            local owner_shares = {}
            for _, value in ipairs(ARGV) do
                owner_shares[value] = true
            end

            -- find all shares that the owner no longer tracks
            local outdated = {}
            local our_shares = redis.call("SMEMBERS", owner_key)
            for _, id in ipairs(our_shares) do
                if not owner_shares[id] then
                    table.insert(outdated, id)
                end
            end

            -- remove the outdated shares from our node
            if #outdated > 0 then
                redis.call("SREM", owner_key, unpack(outdated))
                redis.call("SREM", reserved_key, unpack(outdated))
                redis.call("HDEL", protocol_key, unpack(outdated))
            end

            return outdated
        "#;

        let Some(mut conn) = self.connect().await else {
            return R::default();
        };
        let result: Result<R, _> = redis::Script::new(SCRIPT)
            .key(&self.protocol_key)
            .key(&self.reserved_key)
            .key(self.owner_key(owner))
            // NOTE: this encodes each entry of owner_shares as a separate ARGV[index] entry.
            .arg(owner_shares.into_iter().copied().collect::<Vec<_>>())
            .invoke_async(&mut conn)
            .await;

        match result {
            Ok(outdated) => outdated,
            Err(err) => {
                tracing::warn!(?err, "failed to remove outdated {}s", self.name);
                R::default()
            }
        }
    }

    /// Insert a protocol into the storage. The protocol is owned by the `owner` supplied.
    pub async fn insert(&self, protocol: T, owner: Participant) -> bool {
        const SCRIPT: &str = r#"
            local protocol_key = KEYS[1]
            local used_key = KEYS[2]
            local reserved_key = KEYS[3]
            local owner_keys = KEYS[4]
            local owner_key = KEYS[5]
            local participant_key = KEYS[6]
            local name = KEYS[7]
            local protocol_id = ARGV[1]
            local protocol = ARGV[2]
            local participant_beg = 3
            local participant_end = #ARGV

            -- if the protocol has NOT been reserved, then something went wrong when acquiring the
            -- reservation for it via protocol slot.
            if redis.call("SREM", reserved_key, protocol_id) == 0 then
                return {err = "WARN ".. name .. " " .. protocol_id .. " has NOT been reserved"}
            end

            if redis.call('HEXISTS', used_key, protocol_id) == 1 then
                return {err = 'WARN ' .. name .. ' ' .. protocol_id .. ' is already used'}
            end

            redis.call("SADD", participant_key, unpack(ARGV, participant_beg, participant_end))
            redis.call("SADD", owner_key, protocol_id)
            redis.call("SADD", owner_keys, owner_key)
            redis.call("HSET", protocol_key, protocol_id, protocol)
        "#;

        let id = protocol.id();
        let Some(mut conn) = self.connect().await else {
            tracing::warn!(id, "failed to insert {}: connection failed", self.name);
            return false;
        };

        let participants = protocol
            .participants()
            .iter()
            .copied()
            .map(Into::<u32>::into)
            .collect::<Vec<_>>();
        let outcome = redis::Script::new(SCRIPT)
            .key(&self.protocol_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .key(&self.owner_keys)
            .key(self.owner_key(owner))
            .key(self.participant_key(id))
            .key(&self.name)
            .arg(id)
            .arg(protocol)
            .arg(participants)
            .invoke_async(&mut conn)
            .await;

        match outcome {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(id, ?err, "failed to insert {}", self.name);
                false
            }
        }
    }

    /// Clear all protocols from storage, including used, reserved, and owned keys.
    /// Return true if successful, false otherwise.
    pub async fn clear(&self) -> bool {
        const SCRIPT: &str = r#"
            local owner_keys = redis.call("SMEMBERS", KEYS[1])
            local participant_keys = redis.call("KEYS", KEYS[2] .. ":*")
            local del = {}
            for _, key in ipairs(KEYS) do
                table.insert(del, key)
            end
            for _, key in ipairs(owner_keys) do
                table.insert(del, key)
            end

            redis.call("DEL", unpack(del))
            if #participant_keys > 0 then
                redis.call("DEL", unpack(participant_keys))
            end
        "#;

        let Some(mut conn) = self.connect().await else {
            return false;
        };
        let outcome: Option<()> = redis::Script::new(SCRIPT)
            .key(&self.owner_keys)
            .key(&self.participant_keys)
            .key(&self.protocol_key)
            .key(&self.used_key)
            .key(&self.reserved_key)
            .invoke_async(&mut conn)
            .await
            .inspect_err(|err| {
                tracing::warn!(?err, "failed to clear {} storage", self.name);
            })
            .ok();

        // if the outcome is None, it means the script failed or there was an error.
        outcome.is_some()
    }

    fn owner_key(&self, owner: Participant) -> String {
        format!("{}:p{}", self.owner_keys, Into::<u32>::into(owner))
    }

    fn participant_key(&self, id: T::Id) -> String {
        format!("{}:{}", self.participant_keys, id)
    }
}
