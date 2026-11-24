# Redis connection pooling

The node uses Redis for protocol artifacts (triples, presignatures), checkpoints and the Midnight DUST checkpoint. Storage modules take a pool-like handle (`mpc_node::storage::redis_pool::Pool`) and check out a connection for each command or Lua script.

## Why not deadpool-redis

`deadpool-redis 0.18` pipelines `UNWATCH` + `PING` in `Manager::recycle` on every checkout of an idle connection. That is one extra Redis round trip per storage operation. No newer deadpool-redis version makes the check configurable. A local microbenchmark measured pooled `get()` + PING at ~151 us median versus ~79 us median for a reused `MultiplexedConnection` PING.

## Current design

`chain-signatures/node/src/storage/redis_pool.rs` replaces `deadpool_redis::Pool` with:

- One lazily initialized `redis::aio::ConnectionManager` per pool. It wraps a multiplexed Tokio connection and is `Clone`. Reconnection on I/O errors (including `CLIENT KILL`) is best-effort and single-attempt: the manager config uses `set_number_of_retries(0)`, so a command can fail once before a later command uses the recovered connection. Connection setup happens on first checkout, so building a pool is synchronous and never contacts Redis.
- An `Arc<tokio::sync::Semaphore>` sized to the configured maximum pool size (default `2 × available_parallelism`, similar to - not identical to - deadpool's `num_cpus::get() * 2`). Each checkout holds an owned permit until its `Connection` wrapper is dropped, preserving the concurrency bound.
- A `Connection` wrapper that dereferences to the manager and implements `redis::aio::ConnectionLike`, so existing `AsyncCommands`, `Pipeline::query_async` and `Script::invoke_async(&mut conn)` call sites are unchanged.
- Response and connection timeouts from the caller (5s in the node CLI, 5s by default in the benchmark harness), a bounded wait timeout covering the whole checkout (permit plus lazy connection setup), and `close()` for the harness test that simulates an unusable pool.

The `ConnectionManager` feature must be enabled on the `redis` dependency; deadpool-redis did not enable it.

## Behavior differences and tradeoffs

- There is no per-checkout liveness check. A dead connection is detected by the *real* command, which fails once and triggers a best-effort single-attempt reconnect; later commands await the new connection. The existing retries around `ProtocolStorage::connect()` only cover checkout, as before.
- `UNWATCH` is gone. Neither the node nor the benchmark uses Redis `WATCH`/`MULTI`, so there is no transaction state to clear. If that changes, a new connection or explicit `UNWATCH` will be needed.
- One multiplexed TCP connection replaces up to `max_size` pooled sockets. This removes per-checkout RTTs but means all checkouts share one socket; a server-side stall or network saturation can affect all of them (pipelining, not true parallel sockets). The semaphore still bounds in-flight checkouts.
- Diagnostics `Pool:` line: `max` is the permit limit, `active` is 1 once the shared connection is initialized (0 before), and `available` is the number of free connection slots. These are not deadpool's idle/active socket counts. Key layout, Lua scripts, command sequences and error mapping are unchanged.
