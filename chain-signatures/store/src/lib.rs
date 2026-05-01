pub mod artifact;
pub mod checkpoint;
pub mod keys;

#[cfg(not(test))]
use redis_module::alloc::RedisAlloc;
#[cfg(not(test))]
use redis_module::redis_module;

// Import command handlers
#[cfg(not(test))]
use artifact::{
    artifact_clear, artifact_contains, artifact_contains_by_owner, artifact_fetch_owned,
    artifact_insert, artifact_len_by_owner, artifact_len_generated,
    artifact_remove_holder_and_prune, artifact_remove_outdated, artifact_take, artifact_take_mine,
};
#[cfg(not(test))]
use checkpoint::{checkpoint_load, checkpoint_persist};

// Register the Redis module
#[cfg(not(test))]
redis_module! {
    name: "mpc",
    version: 1,
    allocator: (RedisAlloc, RedisAlloc),
    data_types: [],
    commands: [
        ["mpc.artifact.insert", artifact_insert, "write", 1, 1, 1],
        ["mpc.artifact.take", artifact_take, "write", 1, 1, 1],
        ["mpc.artifact.take_mine", artifact_take_mine, "write", 1, 1, 1],
        ["mpc.artifact.contains", artifact_contains, "readonly", 1, 1, 1],
        ["mpc.artifact.contains_by_owner", artifact_contains_by_owner, "readonly", 1, 1, 1],
        ["mpc.artifact.fetch_owned", artifact_fetch_owned, "readonly", 1, 1, 1],
        ["mpc.artifact.len_generated", artifact_len_generated, "readonly", 1, 1, 1],
        ["mpc.artifact.len_by_owner", artifact_len_by_owner, "readonly", 1, 1, 1],
        ["mpc.artifact.remove_outdated", artifact_remove_outdated, "write", 1, 1, 1],
        ["mpc.artifact.remove_holder_and_prune", artifact_remove_holder_and_prune, "write", 1, 1, 1],
        ["mpc.artifact.clear", artifact_clear, "write", 1, 1, 1],
        ["mpc.checkpoint.persist", checkpoint_persist, "write", 1, 1, 1],
        ["mpc.checkpoint.load", checkpoint_load, "readonly", 1, 1, 1],
    ]
}
