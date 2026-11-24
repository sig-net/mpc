# Redis Benchmark Baseline

- **Date:** 2026-11-23
- **HEAD:** `41a1fc77cc31a0090a30f34b49adc18eb21fad41`
- **Branch:** `continuous.redis.bench`
- **Redis:** 8.4.0, local at `127.0.0.1:6399`, external Redis allowed; Docker was unavailable, so this used a local Redis 8.4.0 server instead of Docker `redis:7.4.12`.
- **Host:** macOS 27.2.1, Apple Silicon (`arm64`), 10 CPUs, 16 GiB RAM.
- **Command:**

  ```sh
  cargo run --release -p integration-tests --bin redis-bench -- --redis-url redis://default:bench@127.0.0.1:6399 --allow-external-redis --json-out tmp/baseline.json --csv-out tmp/baseline.csv 2>&1 | tee tmp/baseline-run.log
  ```

  The first compile attempt hit `No space left on device` on the repository volume. The successful retry used the same command and Redis server, with `CARGO_TARGET_DIR=/private/var/folders/9r/zs_bh5_90rj11vlw571bfs8c0000gn/T/opencode/redis-bench-target` set for build artifacts only.
- **Runtime:** Approximately 8m20s for the successful invocation (6m12s release build, then about 2m08s running the suite).
- **Repeatability:** All subsequent branch benchmarks use the identical benchmark command and Redis server.
- **How to read:** Lower latency and higher goodput/attempts per second are better. Failures and unknown outcomes are excluded from latency percentiles.


## Scenario 1 — Concurrent Insert & Take

```text
Unknown: storage returned no value (unavailable or error); latency samples include successes only.
-------------------------------------------------------------------------------------------------------------------------------------
Operation                  | Samples | Failures |  Unknown |       p50 |       p90 |       p95 |       p99 |       Max | Attempts/s | Goodput/s
-------------------------------------------------------------------------------------------------------------------------------------
concurrent_insert_triple   |    3600 |        0 |        0 |    0.63ms |    0.68ms |    0.71ms |    0.79ms |    1.89ms |    18741.1 |   18741.1
concurrent_take_triple     |    3600 |        0 |        0 |    0.36ms |    0.46ms |    0.64ms |    0.90ms |    1.07ms |    30614.5 |   30614.5

  [Redis Diagnostics]
   Slowlog (>=1ms): None recorded (all commands executed under 1ms)
   Keyspace post-run: 12 keys in Redis (DBSIZE) | Memory: used=1.55M rss=7.88M frag_ratio=2.29 | Pool: max=20 active=1 available=1
```

## Scenario 2 — Stockpile One-Second Polling Contention Comparison

```text
Unknown: storage returned no value (unavailable or error); latency samples include successes only.
-------------------------------------------------------------------------------------------------------------------------------------
Operation                  | Samples | Failures |  Unknown |       p50 |       p90 |       p95 |       p99 |       Max | Attempts/s | Goodput/s
-------------------------------------------------------------------------------------------------------------------------------------
concurrent_insert_triple_no_poll |    1800 |        0 |        0 |    0.64ms |    0.77ms |    0.85ms |    1.32ms |    1.61ms |    17674.6 |   17674.6
concurrent_take_triple_no_poll |    1800 |        0 |        0 |    0.34ms |    0.39ms |    0.41ms |    0.47ms |    0.60ms |    34171.6 |   34171.6
concurrent_insert_triple_with_poll |    1800 |        0 |        0 |    0.62ms |    0.66ms |    0.68ms |    0.73ms |    0.88ms |    19177.2 |   19177.2
concurrent_take_triple_with_poll |    1800 |        0 |        0 |    0.34ms |    0.38ms |    0.40ms |    0.44ms |    0.59ms |    34485.4 |   34485.4

  [Redis Diagnostics]
   Slowlog (>=1ms): None recorded (all commands executed under 1ms)
   Keyspace post-run: 12 keys in Redis (DBSIZE) | Memory: used=1.46M rss=8.11M frag_ratio=5.28 | Pool: max=20 active=1 available=1
```

## Checkpoint Contention (25,000 Pending Requests per Node; additional workload)

```text
Unknown: storage returned no value (unavailable or error); latency samples include successes only.
-------------------------------------------------------------------------------------------------------------------------------------
Operation                  | Samples | Failures |  Unknown |       p50 |       p90 |       p95 |       p99 |       Max | Attempts/s | Goodput/s
-------------------------------------------------------------------------------------------------------------------------------------
concurrent_insert_triple_no_checkpoint |    3600 |        0 |        0 |    0.63ms |    0.68ms |    0.70ms |    0.75ms |    0.85ms |    18918.6 |   18918.6
concurrent_take_triple_no_checkpoint |    3600 |        0 |        0 |    0.34ms |    0.38ms |    0.39ms |    0.43ms |    0.52ms |    34523.5 |   34523.5
concurrent_insert_triple_with_checkpoint |    3600 |        0 |        0 |  178.15ms |  233.09ms |  251.76ms |  284.92ms |  448.06ms |       64.9 |      64.9
concurrent_take_triple_with_checkpoint |    3600 |        0 |        0 |   90.99ms |  134.05ms |  146.80ms |  176.65ms |  208.04ms |      125.3 |     125.3
checkpoint_write           |    3332 |        0 |        0 |  297.35ms |  379.16ms |  402.23ms |  466.84ms | 1025.57ms |       39.5 |      39.5
checkpoint_read            |    5477 |        0 |        0 |  174.36ms |  269.23ms |  300.47ms |  367.13ms |  661.14ms |       65.0 |      65.0

  [Redis Diagnostics]
   Slowlog (top operations >=1ms):
     * ID 5287:    1.73ms | Cmd: GET node-5.testnet:checkpoint:latest:v14:Solana
     * ID 5286:    1.15ms | Cmd: GET node-10.testnet:checkpoint:latest:v14:Solana
     * ID 5285:    1.40ms | Cmd: GET node-7.testnet:checkpoint:latest:v14:Solana
     * ID 5284:    5.08ms | Cmd: GET node-9.testnet:checkpoint:latest:v14:Solana
     * ID 5283:    2.15ms | Cmd: GET node-6.testnet:checkpoint:latest:v14:Solana
     * ID 5282:    1.17ms | Cmd: GET node-1.testnet:checkpoint:latest:v14:Solana
     * ID 5281:    1.20ms | Cmd: GET node-4.testnet:checkpoint:latest:v14:Solana
     * ID 5280:    1.07ms | Cmd: GET node-3.testnet:checkpoint:latest:v14:Solana
     * ID 5279:    1.57ms | Cmd: GET node-0.testnet:checkpoint:latest:v14:Solana
     * ID 5278:    1.56ms | Cmd: GET node-2.testnet:checkpoint:latest:v14:Solana
     * ID 5277:    1.30ms | Cmd: GET node-11.testnet:checkpoint:latest:v14:Solana
     * ID 5276:    2.08ms | Cmd: GET node-7.testnet:checkpoint:latest:v14:Solana
     * ID 5275:    8.40ms | Cmd: GET node-8.testnet:checkpoint:latest:v14:Solana
     * ID 5274:    1.43ms | Cmd: GET node-9.testnet:checkpoint:latest:v14:Solana
     * ID 5273:    1.40ms | Cmd: GET node-10.testnet:checkpoint:latest:v14:Solana
     * ID 5272:    2.29ms | Cmd: GET node-1.testnet:checkpoint:latest:v14:Solana
     * ID 5271:    1.25ms | Cmd: GET node-5.testnet:checkpoint:latest:v14:Solana
     * ID 5270:    1.50ms | Cmd: GET node-4.testnet:checkpoint:latest:v14:Solana
     * ID 5269:    1.03ms | Cmd: GET node-7.testnet:checkpoint:latest:v14:Solana
     * ID 5268:    1.09ms | Cmd: GET node-3.testnet:checkpoint:latest:v14:Solana
   Keyspace post-run: 24 keys in Redis (DBSIZE) | Memory: used=1.01G rss=1.14G frag_ratio=1.07 | Pool: max=20 active=1 available=1
```

## Scenario 3 — `remove_outdated` Pruning Storm

```text
Unknown: storage returned no value (unavailable or error); latency samples include successes only.
-------------------------------------------------------------------------------------------------------------------------------------
Operation                  | Samples | Failures |  Unknown |       p50 |       p90 |       p95 |       p99 |       Max | Attempts/s | Goodput/s
-------------------------------------------------------------------------------------------------------------------------------------
remove_outdated_storm      |     108 |        0 |        0 |    7.29ms |   10.63ms |   13.74ms |   13.98ms |   14.00ms |     1459.0 |    1459.0

  [Redis Diagnostics]
   Slowlog (top operations >=1ms):
     * ID 5290:    2.33ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-10.testnet
     * ID 5289:    1.70ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-7.testnet
     * ID 5288:    1.53ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-0.testnet
   Keyspace post-run: 0 keys in Redis (DBSIZE) | Memory: used=3.29M rss=1.10G frag_ratio=128.56 | Pool: max=20 active=1 available=1
```

## Scenario 4 — Proposer Race (`peek_mine` + `commit`)

```text
Unknown: storage returned no value (unavailable or error); latency samples include successes only.
-------------------------------------------------------------------------------------------------------------------------------------
Operation                  | Samples | Failures |  Unknown |       p50 |       p90 |       p95 |       p99 |       Max | Attempts/s | Goodput/s
-------------------------------------------------------------------------------------------------------------------------------------
peek_mine_contended        |      73 |        0 |      127 |    0.30ms |    0.32ms |    0.33ms |    0.53ms |    0.53ms |     8201.0 |    2993.4
commit_proposal            |      72 |        0 |        1 |    0.31ms |    0.33ms |    0.35ms |    0.64ms |    0.64ms |     2993.4 |    2952.4

  [Redis Diagnostics]
   Slowlog (>=1ms): None recorded (all commands executed under 1ms)
   Keyspace post-run: 231 keys in Redis (DBSIZE) | Memory: used=3.49M rss=1.10G frag_ratio=128.56 | Pool: max=20 active=1 available=1
```

## Scenario 5 — Cascading Saturation & Head-of-Line Blocking

```text
Unknown: storage returned no value (unavailable or error); latency samples include successes only.
-------------------------------------------------------------------------------------------------------------------------------------
Operation                  | Samples | Failures |  Unknown |       p50 |       p90 |       p95 |       p99 |       Max | Attempts/s | Goodput/s
-------------------------------------------------------------------------------------------------------------------------------------
saturated_insert_triple    |    3600 |        0 |        0 |    1.60ms |    1.87ms |    2.04ms |  253.88ms |  254.41ms |    10320.8 |   10320.8
saturated_peek_mine        |    1490 |        0 |       10 |    2.54ms |    2.76ms |    3.01ms |  254.69ms |  254.83ms |     4754.7 |    4723.0
saturated_take_triple      |    3600 |        0 |        0 |    0.99ms |    1.15ms |    1.26ms |  253.00ms |  253.18ms |    11506.2 |   11506.2

  [Redis Diagnostics]
   Slowlog (top operations >=1ms):
     * ID 5293:  252.01ms | Cmd: DEBUG SLEEP 0.250
     * ID 5292:  252.01ms | Cmd: DEBUG SLEEP 0.250
     * ID 5291:  252.02ms | Cmd: DEBUG SLEEP 0.250
   Keyspace post-run: 12 keys in Redis (DBSIZE) | Memory: used=2.64M rss=740.83M frag_ratio=274.09 | Pool: max=20 active=1 available=1
```

## Scenario 6 — Mass Epoch Resharing `clear()` Storm

```text
Unknown: storage returned no value (unavailable or error); latency samples include successes only.
-------------------------------------------------------------------------------------------------------------------------------------
Operation                  | Samples | Failures |  Unknown |       p50 |       p90 |       p95 |       p99 |       Max | Attempts/s | Goodput/s
-------------------------------------------------------------------------------------------------------------------------------------
clear_triples_storm        |     108 |        0 |        0 |    4.64ms |    4.81ms |    4.85ms |    4.88ms |    4.91ms |     2514.3 |    2514.3
clear_presigs_storm        |     108 |        0 |        0 |    4.66ms |    4.83ms |    4.85ms |    4.86ms |    4.89ms |     2514.1 |    2514.1

  [Redis Diagnostics]
   Slowlog (>=1ms): None recorded (all commands executed under 1ms)
   Keyspace post-run: 0 keys in Redis (DBSIZE) | Memory: used=2.59M rss=379.98M frag_ratio=54.42 | Pool: max=20 active=1 available=1
```

## Scenario 7 — Mixed MPC Storage Workload

```text
Unknown: storage returned no value (unavailable or error); latency samples include successes only.
-------------------------------------------------------------------------------------------------------------------------------------
Operation                  | Samples | Failures |  Unknown |       p50 |       p90 |       p95 |       p99 |       Max | Attempts/s | Goodput/s
-------------------------------------------------------------------------------------------------------------------------------------
mixed_insert_triple        |    1200 |        0 |        0 |    1.55ms |    1.66ms |    1.69ms |    1.75ms |    1.89ms |     4736.1 |    4736.1
mixed_presig_peek_triple   |    1200 |        0 |        0 |    0.58ms |    0.85ms |    0.88ms |    0.97ms |    1.08ms |     4736.1 |    4736.1
mixed_presig_commit_triple |    1200 |        0 |        0 |    0.57ms |    0.85ms |    0.88ms |    0.95ms |    1.05ms |     4736.1 |    4736.1
mixed_insert_presig        |    1200 |        0 |        0 |    1.11ms |    1.61ms |    1.64ms |    1.70ms |    1.86ms |     4736.1 |    4736.1
mixed_sign_peek_presig     |     600 |        0 |        0 |    0.78ms |    0.88ms |    0.90ms |    0.97ms |    1.06ms |     2368.1 |    2368.1
mixed_sign_commit_presig   |     600 |        0 |        0 |    0.77ms |    0.86ms |    0.90ms |    0.95ms |    1.10ms |     2368.1 |    2368.1
mixed_sign_take_presig     |    4800 |        0 |        0 |    0.57ms |    0.83ms |    0.87ms |    0.95ms |    1.12ms |    18944.4 |   18944.4

  [Redis Diagnostics]
   Slowlog (>=1ms): None recorded (all commands executed under 1ms)
   Keyspace post-run: 2472 keys in Redis (DBSIZE) | Memory: used=6.62M rss=19.47M frag_ratio=2.94 | Pool: max=20 active=1 available=1
```

## Scenario 8 — State Sync Peer Drop & Pruning

```text
Unknown: storage returned no value (unavailable or error); latency samples include successes only.
-------------------------------------------------------------------------------------------------------------------------------------
Operation                  | Samples | Failures |  Unknown |       p50 |       p90 |       p95 |       p99 |       Max | Attempts/s | Goodput/s
-------------------------------------------------------------------------------------------------------------------------------------
sync_update_triples        |     108 |        0 |        0 |    4.36ms |    4.50ms |    4.51ms |    4.92ms |    4.95ms |     1360.2 |    1360.2
sync_update_presigs        |     108 |        0 |        0 |    4.03ms |    4.98ms |    5.19ms |    5.66ms |    5.76ms |     1360.2 |    1360.2
sync_prune_triples         |     108 |        0 |        0 |    7.27ms |    7.39ms |    7.40ms |    7.42ms |    7.44ms |      835.8 |     835.8
sync_prune_presigs         |     108 |        0 |        0 |    6.87ms |    7.70ms |    8.25ms |    8.32ms |    8.43ms |      835.8 |     835.8

  [Redis Diagnostics]
   Slowlog (>=1ms): None recorded (all commands executed under 1ms)
   Keyspace post-run: 24 keys in Redis (DBSIZE) | Memory: used=2.83M rss=19.80M frag_ratio=2.64 | Pool: max=20 active=1 available=1
```

## Scenario 9 — Connection Drop & Reconnection Shock

```text
Unknown: storage returned no value (unavailable or error); latency samples include successes only.
-------------------------------------------------------------------------------------------------------------------------------------
Operation                  | Samples | Failures |  Unknown |       p50 |       p90 |       p95 |       p99 |       Max | Attempts/s | Goodput/s
-------------------------------------------------------------------------------------------------------------------------------------
insert_under_client_kill   |    3593 |        7 |        0 |    0.63ms |    0.70ms |    0.74ms |    0.84ms |    2.47ms |    18533.6 |   18497.6
take_under_client_kill     |    1789 |        0 |        4 |    0.35ms |    0.38ms |    0.40ms |    0.50ms |    0.88ms |    33691.2 |   33616.1
take_post_reconnect        |    1800 |        0 |        0 |    0.35ms |    0.38ms |    0.39ms |    0.43ms |    0.50ms |    34365.0 |   34365.0

  [Redis Diagnostics]
   Slowlog (>=1ms): None recorded (all commands executed under 1ms)
   Keyspace post-run: 24 keys in Redis (DBSIZE) | Memory: used=1.74M rss=19.89M frag_ratio=6.81 | Pool: max=20 active=1 available=1
```

## Scenario 10 — Large Stockpile Deep-Seek and Presignature Stockpile Seek

```text
Unknown: storage returned no value (unavailable or error); latency samples include successes only.
-------------------------------------------------------------------------------------------------------------------------------------
Operation                  | Samples | Failures |  Unknown |       p50 |       p90 |       p95 |       p99 |       Max | Attempts/s | Goodput/s
-------------------------------------------------------------------------------------------------------------------------------------
deep_peek_mine             |      62 |        0 |      238 |    2.55ms |    3.10ms |    3.12ms |    3.34ms |    3.34ms |     1850.2 |     382.4
deep_commit                |      53 |        0 |        9 |    2.44ms |    2.58ms |    2.62ms |    2.68ms |    2.68ms |      382.4 |     326.9

  [Redis Diagnostics]
   Slowlog (>=1ms): None recorded (all commands executed under 1ms)
   Keyspace post-run: 2950 keys in Redis (DBSIZE) | Memory: used=4.70M rss=21.23M frag_ratio=4.46 | Pool: max=20 active=1 available=1
```

```text
Unknown: storage returned no value (unavailable or error); latency samples include successes only.
-------------------------------------------------------------------------------------------------------------------------------------
Operation                  | Samples | Failures |  Unknown |       p50 |       p90 |       p95 |       p99 |       Max | Attempts/s | Goodput/s
-------------------------------------------------------------------------------------------------------------------------------------
presig_stockpile_peek      |     108 |        0 |       92 |    0.97ms |    1.11ms |    1.14ms |    1.20ms |    1.20ms |     2781.7 |    1502.1
presig_stockpile_commit    |     108 |        0 |        0 |    0.79ms |    1.09ms |    1.11ms |    1.19ms |    1.19ms |     1502.1 |    1502.1

  [Redis Diagnostics]
   Slowlog (>=1ms): None recorded (all commands executed under 1ms)
   Keyspace post-run: 3995 keys in Redis (DBSIZE) | Memory: used=3.77M rss=21.59M frag_ratio=6.00 | Pool: max=20 active=1 available=1
```

## Scenario 11 — Proposer Churn & Aborted Reservation Storm

```text
Unknown: storage returned no value (unavailable or error); latency samples include successes only.
-------------------------------------------------------------------------------------------------------------------------------------
Operation                  | Samples | Failures |  Unknown |       p50 |       p90 |       p95 |       p99 |       Max | Attempts/s | Goodput/s
-------------------------------------------------------------------------------------------------------------------------------------
churn_peek_mine            |      32 |        0 |        0 |    0.23ms |    0.44ms |    0.50ms |    0.57ms |    0.57ms |        1.6 |       1.6
churn_commit               |      17 |        0 |        0 |    0.54ms |    0.84ms |       n/a |       n/a |    0.95ms |        0.8 |       0.8

  [Redis Diagnostics]
   Slowlog (>=1ms): None recorded (all commands executed under 1ms)
   Keyspace post-run: 586 keys in Redis (DBSIZE) | Memory: used=1.85M rss=21.69M frag_ratio=11.71 | Pool: max=20 active=1 available=1
```

## Scenario 12 — Conflicted Double-Take Race Storm

```text
Unknown: storage returned no value (unavailable or error); latency samples include successes only.
-------------------------------------------------------------------------------------------------------------------------------------
Operation                  | Samples | Failures |  Unknown |       p50 |       p90 |       p95 |       p99 |       Max | Attempts/s | Goodput/s
-------------------------------------------------------------------------------------------------------------------------------------
take_contended             |      60 |        0 |      180 |    0.27ms |    0.55ms |    0.55ms |    0.63ms |    0.63ms |    11272.4 |    2818.1

  [Redis Diagnostics]
   Slowlog (>=1ms): None recorded (all commands executed under 1ms)
   Keyspace post-run: 1 keys in Redis (DBSIZE) | Memory: used=1.58M rss=21.69M frag_ratio=11.71 | Pool: max=20 active=1 available=1
```

## Scenario 13 — Large-Batch & ARGV Outdated Pruning

```text
Unknown: storage returned no value (unavailable or error); latency samples include successes only.
-------------------------------------------------------------------------------------------------------------------------------------
Operation                  | Samples | Failures |  Unknown |       p50 |       p90 |       p95 |       p99 |       Max | Attempts/s | Goodput/s
-------------------------------------------------------------------------------------------------------------------------------------
large_argv_sync            |      20 |        0 |        0 |    5.34ms |    7.38ms |    8.14ms |   10.29ms |   10.29ms |      168.7 |     168.7
large_outdated_prune       |      20 |        0 |        0 |    4.87ms |    6.07ms |    7.02ms |   18.73ms |   18.73ms |      174.2 |     174.2

  [Redis Diagnostics]
   Slowlog (top operations >=1ms):
     * ID 5338:    4.76ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-1.testnet
     * ID 5337:    4.66ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-1.testnet
     * ID 5336:    4.50ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-0.testnet
     * ID 5335:    4.48ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-0.testnet
     * ID 5334:    4.27ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-1.testnet
     * ID 5333:    4.40ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-1.testnet
     * ID 5332:   17.34ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-0.testnet
     * ID 5331:    5.67ms | Cmd: SREM triples_owners:v12:node-0.testnet:p0 10794225 10792920
     * ID 5330:    1.74ms | Cmd: HDEL triples:v12:node-0.testnet 10794082 10792791
     * ID 5329:    7.19ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-0.testnet
     * ID 5328:    4.02ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-1.testnet
     * ID 5327:    4.50ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-1.testnet
     * ID 5326:    4.60ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-0.testnet
     * ID 5325:    9.37ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-0.testnet
     * ID 5324:    1.22ms | Cmd: EVALSHA 4cdbe70150d9330e8b134a214806a6f53f3ac576 3 triples:v12:node-0.testnet
     * ID 5323:    1.24ms | Cmd: EVALSHA 4cdbe70150d9330e8b134a214806a6f53f3ac576 3 triples:v12:node-0.testnet
     * ID 5322:    5.09ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-1.testnet
     * ID 5321:    4.83ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-1.testnet
     * ID 5320:    4.57ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-0.testnet
     * ID 5319:    5.11ms | Cmd: EVALSHA f2f10970062d51c57482ba6716bf773fe060b01c 2 triples:v12:node-0.testnet
   Keyspace post-run: 0 keys in Redis (DBSIZE) | Memory: used=1.94M rss=20.17M frag_ratio=3.24 | Pool: max=20 active=1 available=1
```

## Scenario 14 — Real AOF & BGSAVE Disk Persistence Stalls

```text
Unknown: storage returned no value (unavailable or error); latency samples include successes only.
-------------------------------------------------------------------------------------------------------------------------------------
Operation                  | Samples | Failures |  Unknown |       p50 |       p90 |       p95 |       p99 |       Max | Attempts/s | Goodput/s
-------------------------------------------------------------------------------------------------------------------------------------
in_memory_insert           |     720 |        0 |        0 |    0.69ms |    1.26ms |    1.46ms |    1.72ms |    1.77ms |    14909.7 |   14909.7
aof_fsync_insert           |     720 |        0 |        0 |   16.12ms |   22.04ms |   24.01ms |   28.05ms |   32.05ms |      723.4 |     723.4
bgsave_concurrent_take     |     720 |        0 |        0 |   13.95ms |   15.07ms |   15.95ms |   22.08ms |   23.00ms |      880.0 |     880.0

  [Redis Diagnostics]
   Slowlog (top operations >=1ms):
     * ID 5341:   10.35ms | Cmd: CONFIG SET appendonly no
     * ID 5340:    2.75ms | Cmd: CONFIG SET appendonly yes
     * ID 5339:    3.31ms | Cmd: CONFIG SET appendonly no
   Keyspace post-run: 0 keys in Redis (DBSIZE) | Memory: used=1.87M rss=20.66M frag_ratio=7.74 | Pool: max=20 active=1 available=1
```
## Selected baseline operations

| Operation | p50 | p95 | Goodput/s |
|---|---:|---:|---:|
| `concurrent_insert_triple` (insert) | 0.63ms | 0.71ms | 18741.1 |
| `concurrent_take_triple` (take) | 0.36ms | 0.64ms | 30614.5 |
| `peek_mine_contended` (peek) | 0.30ms | 0.33ms | 2993.4 |
| `commit_proposal` (commit) | 0.31ms | 0.35ms | 2952.4 |
| `remove_outdated_storm` (`remove_outdated`) | 7.29ms | 13.74ms | 1459.0 |
| `clear_triples_storm` (`clear`) | 4.64ms | 4.85ms | 2514.3 |
| `clear_presigs_storm` (`clear`) | 4.66ms | 4.85ms | 2514.1 |

## Failures and anomalies

- `insert_under_client_kill` reported **7 failures** (3,593 samples; 0 unknown). This is the only printed nonzero failure count.
- Unknown outcomes were reported for `peek_mine_contended` (127), `commit_proposal` (1), `saturated_peek_mine` (10), `take_under_client_kill` (4), `deep_peek_mine` (238), `deep_commit` (9), `presig_stockpile_peek` (92), and `take_contended` (180). As noted above, unknown outcomes are excluded from latency percentiles.
- The initial compilation attempt failed because the repository volume was full; the benchmark completed successfully on retry using an external Cargo target directory.
