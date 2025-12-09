use redis_module::{redis_module, Context, RedisResult, RedisString, RedisValue, RedisError};

/// MPC.RESERVE artifact_key used_key reserved_key artifact_id
///
/// Atomically reserves an artifact slot. Succeeds only when:
/// - artifact_id does not exist in artifact_key hash
/// - artifact_id is not in used_key hash
/// - artifact_id is not already in reserved_key set
///
/// Returns: OK on success, error on failure
fn reserve_command(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    // Validate argument count: command name + 4 arguments
    if args.len() != 5 {
        return Err(RedisError::String("ERR VALIDATION wrong number of arguments for MPC.RESERVE".to_string()));
    }

    let artifact_key = &args[1];
    let used_key = &args[2];
    let reserved_key = &args[3];
    let artifact_id = &args[4];

    // Check if artifact already exists in artifact_key hash
    let artifact_exists: bool = ctx.call("HEXISTS", &[artifact_key, artifact_id])
        .and_then(|v| match v {
            RedisValue::Integer(i) => Ok(i != 0),
            _ => Err(RedisError::String("ERR SYSTEM unexpected response type from HEXISTS".to_string())),
        })?;

    if artifact_exists {
        return Err(RedisError::String("ERR STATE artifact already exists in storage".to_string()));
    }

    // Check if artifact is already marked as used
    let artifact_used: bool = ctx.call("HEXISTS", &[used_key, artifact_id])
        .and_then(|v| match v {
            RedisValue::Integer(i) => Ok(i != 0),
            _ => Err(RedisError::String("ERR SYSTEM unexpected response type from HEXISTS".to_string())),
        })?;

    if artifact_used {
        return Err(RedisError::String("ERR STATE artifact has already been used".to_string()));
    }

    // Check if artifact is already reserved
    let already_reserved: bool = ctx.call("SISMEMBER", &[reserved_key, artifact_id])
        .and_then(|v| match v {
            RedisValue::Integer(i) => Ok(i != 0),
            _ => Err(RedisError::String("ERR SYSTEM unexpected response type from SISMEMBER".to_string())),
        })?;

    if already_reserved {
        return Err(RedisError::String("ERR STATE artifact is already reserved".to_string()));
    }

    // Add artifact_id to reserved set
    ctx.call("SADD", &[reserved_key, artifact_id])?;

    Ok("OK".into())
}

/// MPC.INSERT artifact_key used_key reserved_key owner_keys owner_key artifact_id artifact_data
///
/// Atomically inserts an artifact. Succeeds only when:
/// - artifact_id is in reserved_key set (will be removed)
/// - artifact_id is not in used_key hash
/// - artifact_data is provided
///
/// Returns: OK on success, error on failure
fn insert_command(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    // Validate argument count: command name + 7 arguments
    if args.len() != 8 {
        return Err(RedisError::String("ERR VALIDATION wrong number of arguments for MPC.INSERT".to_string()));
    }

    let artifact_key = &args[1];
    let used_key = &args[2];
    let reserved_key = &args[3];
    let owner_keys = &args[4];
    let owner_key = &args[5];
    let artifact_id = &args[6];
    let artifact_data = &args[7];

    // Check if artifact_id is in reserved_key set
    let is_reserved: bool = ctx.call("SISMEMBER", &[reserved_key, artifact_id])
        .and_then(|v| match v {
            RedisValue::Integer(i) => Ok(i != 0),
            _ => Err(RedisError::String("ERR SYSTEM unexpected response type from SISMEMBER".to_string())),
        })?;

    if !is_reserved {
        return Err(RedisError::String("ERR STATE artifact is not reserved".to_string()));
    }

    // Check if artifact is already marked as used
    let artifact_used: bool = ctx.call("HEXISTS", &[used_key, artifact_id])
        .and_then(|v| match v {
            RedisValue::Integer(i) => Ok(i != 0),
            _ => Err(RedisError::String("ERR SYSTEM unexpected response type from HEXISTS".to_string())),
        })?;

    if artifact_used {
        return Err(RedisError::String("ERR STATE artifact has already been used".to_string()));
    }

    // Remove artifact_id from reserved_key set
    ctx.call("SREM", &[reserved_key, artifact_id])?;

    // Add artifact_id to owner_key set
    ctx.call("SADD", &[owner_key, artifact_id])?;

    // Add owner_key to owner_keys set
    ctx.call("SADD", &[owner_keys, owner_key])?;

    // Store artifact in artifact_key hash
    ctx.call("HSET", &[artifact_key, artifact_id, artifact_data])?;

    Ok("OK".into())
}

/// MPC.TAKE artifact_key used_key owner_key artifact_id
///
/// Atomically takes an artifact. Succeeds only when:
/// - artifact_id is not in used_key hash
/// - artifact_id is in owner_key set (will be removed)
/// - artifact_id exists in artifact_key hash
///
/// Returns: artifact data on success, error on failure
fn take_command(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    // Validate argument count: command name + 4 arguments
    if args.len() != 5 {
        return Err(RedisError::String("ERR VALIDATION wrong number of arguments for MPC.TAKE".to_string()));
    }

    let artifact_key = &args[1];
    let used_key = &args[2];
    let owner_key = &args[3];
    let artifact_id = &args[4];

    // Check if artifact is already marked as used
    let artifact_used: bool = ctx.call("HEXISTS", &[used_key, artifact_id])
        .and_then(|v| match v {
            RedisValue::Integer(i) => Ok(i != 0),
            _ => Err(RedisError::String("ERR SYSTEM unexpected response type from HEXISTS".to_string())),
        })?;

    if artifact_used {
        return Err(RedisError::String("ERR STATE artifact has already been used".to_string()));
    }

    // Check if artifact_id is in owner_key set
    let is_owned: bool = ctx.call("SISMEMBER", &[owner_key, artifact_id])
        .and_then(|v| match v {
            RedisValue::Integer(i) => Ok(i != 0),
            _ => Err(RedisError::String("ERR SYSTEM unexpected response type from SISMEMBER".to_string())),
        })?;

    if !is_owned {
        return Err(RedisError::String("ERR STATE artifact is not owned by specified owner".to_string()));
    }

    // Get artifact from artifact_key hash
    let artifact_data = ctx.call("HGET", &[artifact_key, artifact_id])?;

    // Check if artifact exists in storage
    if matches!(artifact_data, RedisValue::Null) {
        return Err(RedisError::String("ERR STATE artifact does not exist in storage".to_string()));
    }

    // Remove artifact_id from owner_key set
    ctx.call("SREM", &[owner_key, artifact_id])?;

    // Mark as used in used_key hash
    let used_marker = RedisString::create(None, "1");
    ctx.call("HSET", &[used_key, artifact_id, &used_marker])?;

    // Delete from artifact_key hash
    ctx.call("HDEL", &[artifact_key, artifact_id])?;

    Ok(artifact_data)
}

/// MPC.TAKE_MINE artifact_key used_key mine_key reserved_key expire_seconds
///
/// Atomically takes an artifact from the owner's set. Returns nil if the owner set is empty.
/// When successful:
/// - Pops one artifact_id from mine_key set
/// - Gets artifact from artifact_key hash
/// - Adds artifact_id back to reserved_key set
/// - Deletes from artifact_key hash
/// - Marks as used in used_key hash with expiration
/// - Returns artifact data
///
/// Returns: artifact data on success, nil if owner set is empty, error on failure
fn take_mine_command(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    // Validate argument count: command name + 5 arguments
    if args.len() != 6 {
        return Err(RedisError::String("ERR VALIDATION wrong number of arguments for MPC.TAKE_MINE".to_string()));
    }

    let artifact_key = &args[1];
    let used_key = &args[2];
    let mine_key = &args[3];
    let reserved_key = &args[4];
    let expire_seconds = &args[5];

    // Check if mine_key set has any members
    let set_cardinality: i64 = ctx.call("SCARD", &[mine_key])
        .and_then(|v| match v {
            RedisValue::Integer(i) => Ok(i),
            _ => Err(RedisError::String("ERR SYSTEM unexpected response type from SCARD".to_string())),
        })?;

    if set_cardinality == 0 {
        return Ok(RedisValue::Null);
    }

    // Pop one artifact_id from mine_key set
    let artifact_id = ctx.call("SPOP", &[mine_key])?;

    // Check if artifact_id is null (shouldn't happen if cardinality > 0, but be safe)
    if matches!(artifact_id, RedisValue::Null) {
        return Ok(RedisValue::Null);
    }

    // Extract the artifact_id as a RedisString for further operations
    let artifact_id_str = match &artifact_id {
        RedisValue::BulkString(bytes) => {
            RedisString::create(None, bytes.as_str())
        },
        _ => return Err(RedisError::String("ERR SYSTEM unexpected response type from SPOP".to_string())),
    };

    // Get artifact from artifact_key hash
    let artifact_data = ctx.call("HGET", &[artifact_key, &artifact_id_str])?;

    // Check if artifact exists in storage
    if matches!(artifact_data, RedisValue::Null) {
        return Err(RedisError::String("ERR STATE artifact does not exist in storage".to_string()));
    }

    // Add artifact_id back to reserved_key set
    ctx.call("SADD", &[reserved_key, &artifact_id_str])?;

    // Delete from artifact_key hash
    ctx.call("HDEL", &[artifact_key, &artifact_id_str])?;

    // Mark as used in used_key hash with expiration
    let used_marker = RedisString::create(None, "1");
    ctx.call("HSET", &[used_key, &artifact_id_str, &used_marker])?;

    // Set expiration on the used_key hash field
    // Note: Redis doesn't support per-field expiration on hashes, so we set expiration on the entire key
    // This is a limitation, but we'll set it on the used_key itself
    ctx.call("EXPIRE", &[used_key, expire_seconds])?;

    Ok(artifact_data)
}

/// MPC.RECYCLE_MINE artifact_key used_key mine_key reserved_key artifact_id artifact_data
///
/// Atomically recycles an artifact back to the owner's set. Succeeds only when:
/// - artifact_id is in used_key hash (will be removed)
/// - artifact_data is provided
///
/// Returns: Integer 1 on success, error on failure
fn recycle_mine_command(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    // Validate argument count: command name + 6 arguments
    if args.len() != 7 {
        return Err(RedisError::String("ERR VALIDATION wrong number of arguments for MPC.RECYCLE_MINE".to_string()));
    }

    let artifact_key = &args[1];
    let used_key = &args[2];
    let mine_key = &args[3];
    let reserved_key = &args[4];
    let artifact_id = &args[5];
    let artifact_data = &args[6];

    // Check if artifact_id is in used_key hash
    let is_used: bool = ctx.call("HEXISTS", &[used_key, artifact_id])
        .and_then(|v| match v {
            RedisValue::Integer(i) => Ok(i != 0),
            _ => Err(RedisError::String("ERR SYSTEM unexpected response type from HEXISTS".to_string())),
        })?;

    if !is_used {
        return Err(RedisError::String("ERR STATE artifact is not marked as used".to_string()));
    }

    // Remove artifact_id from used_key hash
    ctx.call("HDEL", &[used_key, artifact_id])?;

    // Store artifact in artifact_key hash
    ctx.call("HSET", &[artifact_key, artifact_id, artifact_data])?;

    // Add artifact_id to mine_key set
    ctx.call("SADD", &[mine_key, artifact_id])?;

    // Ensure artifact_id is in reserved_key set
    ctx.call("SADD", &[reserved_key, artifact_id])?;

    Ok(RedisValue::Integer(1))
}

/// MPC.REMOVE_OUTDATED artifact_key reserved_key owner_key [owner_share_ids...]
///
/// Atomically removes outdated artifacts. Succeeds by:
/// - Getting all members from owner_key set
/// - Building hash table of owner_share_ids for O(1) lookup
/// - Identifying outdated IDs (in owner_key but not in owner_share_ids)
/// - Batch deleting in chunks to avoid blocking Redis
/// - Removing from owner_key, reserved_key, and artifact_key
/// - Returning list of removed IDs
///
/// Returns: Array of removed artifact IDs
fn remove_outdated_command(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    // Validate argument count: command name + at least 3 arguments (artifact_key, reserved_key, owner_key)
    if args.len() < 4 {
        return Err(RedisError::String("ERR VALIDATION wrong number of arguments for MPC.REMOVE_OUTDATED".to_string()));
    }

    let artifact_key = &args[1];
    let reserved_key = &args[2];
    let owner_key = &args[3];
    let owner_share_ids = &args[4..];

    // Get all members from owner_key set
    let owner_members = ctx.call("SMEMBERS", &[owner_key])?;

    // Extract member IDs from the response
    let member_ids: Vec<String> = match owner_members {
        RedisValue::Array(members) => {
            members.into_iter()
                .filter_map(|m| match m {
                    RedisValue::BulkString(s) => Some(s),
                    _ => None,
                })
                .collect()
        },
        _ => return Err(RedisError::String("ERR SYSTEM unexpected response type from SMEMBERS".to_string())),
    };

    // Build hash set of owner_share_ids for O(1) lookup
    let mut current_ids = std::collections::HashSet::new();
    for id in owner_share_ids {
        let id_str = id.to_string();
        current_ids.insert(id_str);
    }

    // Identify outdated IDs (in owner_key but not in owner_share_ids)
    let mut outdated_ids = Vec::new();
    for member_id in &member_ids {
        if !current_ids.contains(member_id) {
            outdated_ids.push(member_id.clone());
        }
    }

    // Batch delete in chunks of 4096 to avoid blocking Redis
    const BATCH_SIZE: usize = 4096;
    for chunk in outdated_ids.chunks(BATCH_SIZE) {
        // Build delete arguments: command + artifact_key + all IDs in chunk
        let mut delete_args: Vec<&RedisString> = vec![artifact_key];
        let chunk_strings: Vec<RedisString> = chunk.iter()
            .map(|id| RedisString::create(None, id.as_str()))
            .collect();
        for id_str in &chunk_strings {
            delete_args.push(id_str);
        }
        ctx.call("HDEL", delete_args.as_slice())?;

        // Remove from reserved_key set
        let mut reserved_args: Vec<&RedisString> = vec![reserved_key];
        let reserved_strings: Vec<RedisString> = chunk.iter()
            .map(|id| RedisString::create(None, id.as_str()))
            .collect();
        for id_str in &reserved_strings {
            reserved_args.push(id_str);
        }
        ctx.call("SREM", reserved_args.as_slice())?;

        // Remove from owner_key set
        let mut owner_args: Vec<&RedisString> = vec![owner_key];
        let owner_strings: Vec<RedisString> = chunk.iter()
            .map(|id| RedisString::create(None, id.as_str()))
            .collect();
        for id_str in &owner_strings {
            owner_args.push(id_str);
        }
        ctx.call("SREM", owner_args.as_slice())?;
    }

    // Return array of removed IDs
    let removed_array: Vec<RedisValue> = outdated_ids
        .into_iter()
        .map(|id| RedisValue::BulkString(id))
        .collect();

    Ok(RedisValue::Array(removed_array))
}

/// MPC.CLEAR owner_keys artifact_key used_key reserved_key
///
/// Atomically clears all artifact-related keys. Succeeds by:
/// - Getting all members from owner_keys set
/// - Building list of all keys to delete (includes dynamic owner keys)
/// - Deleting all keys in one operation
/// - Returning success indicator
///
/// Returns: OK on success, error on failure
fn clear_command(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    // Validate argument count: command name + 4 arguments
    if args.len() != 5 {
        return Err(RedisError::String("ERR VALIDATION wrong number of arguments for MPC.CLEAR".to_string()));
    }

    let owner_keys = &args[1];
    let artifact_key = &args[2];
    let used_key = &args[3];
    let reserved_key = &args[4];

    // Get all members from owner_keys set
    let owner_members = ctx.call("SMEMBERS", &[owner_keys])?;

    // Extract owner key strings from the response
    let owner_key_strings: Vec<String> = match owner_members {
        RedisValue::Array(members) => {
            members.into_iter()
                .filter_map(|m| match m {
                    RedisValue::BulkString(s) => Some(s),
                    _ => None,
                })
                .collect()
        },
        _ => return Err(RedisError::String("ERR SYSTEM unexpected response type from SMEMBERS".to_string())),
    };

    // Build list of all keys to delete
    let mut keys_to_delete: Vec<RedisString> = Vec::new();
    
    // Add the main keys
    keys_to_delete.push(artifact_key.clone());
    keys_to_delete.push(used_key.clone());
    keys_to_delete.push(reserved_key.clone());
    keys_to_delete.push(owner_keys.clone());

    // Add all dynamic owner keys
    for owner_key_str in owner_key_strings {
        keys_to_delete.push(RedisString::create(None, owner_key_str.as_str()));
    }

    // Delete all keys in one operation
    if !keys_to_delete.is_empty() {
        // Convert Vec<RedisString> to Vec<&RedisString> for the call
        let key_refs: Vec<&RedisString> = keys_to_delete.iter().collect();
        ctx.call("DEL", key_refs.as_slice())?;
    }

    Ok("OK".into())
}

// Module entry point - registers all MPC commands
redis_module! {
    name: "mpc",
    version: 1,
    allocator: (redis_module::alloc::RedisAlloc, redis_module::alloc::RedisAlloc),
    data_types: [],
    commands: [
        ["MPC.RESERVE", reserve_command, "write", 1, 1, 1],
        ["MPC.INSERT", insert_command, "write", 1, 1, 1],
        ["MPC.TAKE", take_command, "write", 1, 1, 1],
        ["MPC.TAKE_MINE", take_mine_command, "write", 1, 1, 1],
        ["MPC.RECYCLE_MINE", recycle_mine_command, "write", 1, 1, 1],
        ["MPC.REMOVE_OUTDATED", remove_outdated_command, "write", 1, 1, 1],
        ["MPC.CLEAR", clear_command, "write", 1, 1, 1],
    ],
}

#[cfg(test)]
pub mod test_utils {
    use std::collections::HashMap;
    use testcontainers::{
        core::{IntoContainerPort, WaitFor},
        runners::AsyncRunner,
        ContainerAsync, GenericImage, ImageExt,
    };
    use near_account_id::AccountId;

    pub type Container = ContainerAsync<GenericImage>;

    pub struct Redis {
        pub container: Container,
        pub internal_address: String,
        pub external_address: String,
    }

    impl Redis {
        const DEFAULT_REDIS_PORT: u16 = 6379;

        pub async fn run(network: &str) -> Self {
            tracing::info!("Running Redis container...");
            let container = GenericImage::new("redis", "7.4.2")
                .with_exposed_port(Self::DEFAULT_REDIS_PORT.tcp())
                .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
                .with_network(network)
                .start()
                .await
                .unwrap();

            // Get network IP using Docker API
            let docker = bollard::Docker::connect_with_local_defaults().unwrap();
            let network_ip = get_network_ip_address(&docker, &container, network)
                .await
                .unwrap();

            let external_address = format!("redis://{}:{}", network_ip, Self::DEFAULT_REDIS_PORT);

            let host_port = container
                .get_host_port_ipv4(Self::DEFAULT_REDIS_PORT)
                .await
                .unwrap();
            let internal_address = format!("redis://127.0.0.1:{host_port}");

            tracing::info!(
                external_address,
                internal_address,
                "Redis container is running",
            );

            Self {
                container,
                internal_address,
                external_address,
            }
        }

        pub fn pool(&self) -> deadpool_redis::Pool {
            let redis_url = url::Url::parse(self.internal_address.as_str()).unwrap();
            let redis_cfg = deadpool_redis::Config::from_url(redis_url);
            redis_cfg
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .unwrap()
        }

        pub fn triple_storage(&self, id: &AccountId) -> TripleStorage {
            TriplePair::storage(&self.pool(), id)
        }

        pub fn presignature_storage(&self, id: &AccountId) -> PresignatureStorage {
            Presignature::storage(&self.pool(), id)
        }

        pub async fn stockpile_triples<C>(&self, cfg: &C, participants: &Participants, mul: u32)
        where
            C: StockpileConfig,
        {
            use cait_sith::protocol::Participant;
            use cait_sith::triples::{TriplePub, TripleShare};
            use elliptic_curve::rand_core::OsRng;
            use k256::Secp256k1;

            let pool = self.pool();
            let storage = participants
                .participants
                .keys()
                .map(|account_id| {
                    (
                        Participant::from(
                            *participants
                                .account_to_participant_id
                                .get(account_id)
                                .unwrap(),
                        ),
                        TriplePair::storage(&pool, account_id),
                    )
                })
                .collect::<HashMap<_, _>>();

            let participant_ids = participants
                .account_to_participant_id
                .values()
                .map(|id| Participant::from(*id))
                .collect::<Vec<_>>();
            let (public, shares): (TriplePub<Secp256k1>, Vec<TripleShare<Secp256k1>>) =
                cait_sith::triples::deal(&mut OsRng, &participant_ids, cfg.threshold());

            let mut num_pairs = 0;
            for owner in &participant_ids {
                for _ in 0..(cfg.min_triples() * mul / 2) {
                    num_pairs += 1;
                    let pair_id = rand::random();
                    for ((me, triple0), triple1) in participant_ids
                        .iter()
                        .zip(shares_to_triples(&public, &shares))
                        .zip(shares_to_triples(&public, &shares))
                    {
                        let pair = TriplePair {
                            id: pair_id,
                            triple0,
                            triple1,
                        };
                        storage
                            .get(me)
                            .unwrap()
                            .reserve(pair_id)
                            .await
                            .unwrap()
                            .insert(pair, *owner)
                            .await;
                    }
                }
            }

            tracing::info!("stockpiled {num_pairs} triple pairs");
        }
    }

    // Trait to abstract over different config types
    pub trait StockpileConfig {
        fn threshold(&self) -> usize;
        fn min_triples(&self) -> u32;
    }

    async fn get_network_ip_address(
        docker: &bollard::Docker,
        container: &Container,
        network: &str,
    ) -> anyhow::Result<String> {
        use anyhow::anyhow;

        let network_settings = docker
            .inspect_container(container.id(), None)
            .await?
            .network_settings
            .ok_or_else(|| anyhow!("missing NetworkSettings on container '{}'", container.id()))?;
        let ip_address = network_settings
            .networks
            .ok_or_else(|| {
                anyhow!(
                    "missing NetworkSettings.Networks on container '{}'",
                    container.id()
                )
            })?
            .get(network)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "container '{}' is not a part of network '{}'",
                    container.id(),
                    network
                )
            })?
            .ip_address
            .ok_or_else(|| {
                anyhow!(
                    "container '{}' belongs to network '{}', but is not assigned an IP address",
                    container.id(),
                    network
                )
            })?;

        Ok(ip_address)
    }

    fn shares_to_triples(
        public: &cait_sith::triples::TriplePub<k256::Secp256k1>,
        shares: &[cait_sith::triples::TripleShare<k256::Secp256k1>],
    ) -> Vec<Triple> {
        shares
            .iter()
            .map(|share| Triple {
                public: public.clone(),
                share: share.clone(),
            })
            .collect()
    }

    // Type aliases to match the integration-tests usage
    pub type Triple = mpc_node::protocol::triple::Triple;
    pub type TriplePair = mpc_node::storage::triple_storage::TriplePair;
    pub type TripleStorage = mpc_node::storage::TripleStorage;
    pub type Presignature = mpc_node::protocol::presignature::Presignature;
    pub type PresignatureStorage = mpc_node::storage::PresignatureStorage;
    pub type Participants = mpc_contract::primitives::Participants;
}
