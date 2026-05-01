pub mod artifact;
pub mod checkpoint;
pub mod keys;

#[cfg(not(test))]
use redis_module::alloc::RedisAlloc;
#[cfg(not(test))]
use redis_module::redis_module;

// Register the Redis module
#[cfg(not(test))]
redis_module! {
    name: "mpc",
    version: 1,
    allocator: (RedisAlloc, RedisAlloc),
    data_types: [],
    commands: [
        ["mpc.artifact.insert", artifact::insert, "write", 1, 1, 1],
        ["mpc.artifact.take", artifact::take, "write", 1, 1, 1],
        ["mpc.artifact.take_mine", artifact::take_mine, "write", 1, 1, 1],
        ["mpc.artifact.contains", artifact::contains, "readonly", 1, 1, 1],
        ["mpc.artifact.contains_by_owner", artifact::contains_by_owner, "readonly", 1, 1, 1],
        ["mpc.artifact.fetch_owned", artifact::fetch_owned, "readonly", 1, 1, 1],
        ["mpc.artifact.len_generated", artifact::len_generated, "readonly", 1, 1, 1],
        ["mpc.artifact.len_by_owner", artifact::len_by_owner, "readonly", 1, 1, 1],
        ["mpc.artifact.remove_outdated", artifact::remove_outdated, "write", 1, 1, 1],
        ["mpc.artifact.remove_holder_and_prune", artifact::remove_holder_and_prune, "write", 1, 1, 1],
        ["mpc.artifact.clear", artifact::clear, "write", 1, 1, 1],
        ["mpc.checkpoint.persist", checkpoint::persist, "write", 1, 1, 1],
        ["mpc.checkpoint.load", checkpoint::load, "readonly", 1, 1, 1],
    ]
}
