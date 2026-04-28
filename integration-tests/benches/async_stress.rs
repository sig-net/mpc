use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

fn bench_task_spawn(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("async_task_spawn");

    for tasks in [16usize, 64, 256] {
        group.bench_with_input(BenchmarkId::new("spawn_yield", tasks), &tasks, |b, &tasks| {
            b.iter(|| {
                rt.block_on(async {
                    let handles: Vec<_> = (0..tasks)
                        .map(|_| tokio::spawn(async { tokio::task::yield_now().await }))
                        .collect();

                    for handle in handles {
                        handle.await.unwrap();
                    }
                })
            })
        });
    }

    group.finish();
}

fn bench_mpsc_throughput(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("async_mpsc");

    for messages in [256usize, 1024, 4096] {
        group.bench_with_input(BenchmarkId::new("send_recv", messages), &messages, |b, &messages| {
            b.iter(|| {
                rt.block_on(async {
                    let (tx, mut rx) = mpsc::channel::<usize>(messages);
                    let sender = tokio::spawn(async move {
                        for i in 0..messages {
                            tx.send(i).await.unwrap();
                        }
                    });

                    let mut received = 0usize;
                    while received < messages {
                        rx.recv().await.unwrap();
                        received += 1;
                    }

                    sender.await.unwrap();
                })
            })
        });
    }

    group.finish();
}

fn bench_broadcast_throughput(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("async_broadcast");

    for messages in [256usize, 1024] {
        group.bench_with_input(BenchmarkId::new("fanout_4", messages), &messages, |b, &messages| {
            b.iter(|| {
                rt.block_on(async {
                    let (tx, _) = broadcast::channel::<usize>(messages);
                    let mut receivers = vec![tx.subscribe(), tx.subscribe(), tx.subscribe(), tx.subscribe()];

                    let receiver_task = tokio::spawn(async move {
                        for rx in &mut receivers {
                            let mut received = 0usize;
                            while received < messages {
                                rx.recv().await.unwrap();
                                received += 1;
                            }
                        }
                    });

                    for i in 0..messages {
                        tx.send(i).unwrap();
                    }

                    receiver_task.await.unwrap();
                })
            })
        });
    }

    group.finish();
}

fn bench_mutex_contention(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("async_mutex");

    for workers in [2usize, 4, 8] {
        group.bench_with_input(BenchmarkId::new("contended_increment", workers), &workers, |b, &workers| {
            b.iter(|| {
                rt.block_on(async {
                    let shared = Arc::new(Mutex::new(0usize));
                    let updates = 512usize;
                    let mut handles = Vec::with_capacity(workers);

                    for _ in 0..workers {
                        let shared = shared.clone();
                        handles.push(tokio::spawn(async move {
                            for _ in 0..updates {
                                *shared.lock().await += 1;
                            }
                        }));
                    }

                    for handle in handles {
                        handle.await.unwrap();
                    }

                    let total = *shared.lock().await;
                    assert_eq!(total, workers * updates);
                })
            })
        });
    }

    group.finish();
}

fn bench_rwlock_contention(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("async_rwlock");

    for readers in [2usize, 4, 8] {
        group.bench_with_input(BenchmarkId::new("mixed_read_write", readers), &readers, |b, &readers| {
            b.iter(|| {
                rt.block_on(async {
                    let shared = Arc::new(RwLock::new(0usize));
                    let counter = Arc::new(AtomicUsize::new(0));
                    let mut handles = Vec::with_capacity(readers + 1);

                    for _ in 0..readers {
                        let shared = shared.clone();
                        let counter = counter.clone();
                        handles.push(tokio::spawn(async move {
                            for _ in 0..256usize {
                                let value = *shared.read().await;
                                counter.fetch_add(value, Ordering::Relaxed);
                            }
                        }));
                    }

                    let shared_for_write = shared.clone();
                    handles.push(tokio::spawn(async move {
                        for _ in 0..256usize {
                            *shared_for_write.write().await += 1;
                        }
                    }));

                    for handle in handles {
                        handle.await.unwrap();
                    }

                    assert_eq!(*shared.read().await, 256usize);
                })
            })
        });
    }

    group.finish();
}

fn bench_async_stress(c: &mut Criterion) {
    bench_task_spawn(c);
    bench_mpsc_throughput(c);
    bench_broadcast_throughput(c);
    bench_mutex_contention(c);
    bench_rwlock_contention(c);
}

criterion_group!(async_stress_benches, bench_async_stress);
criterion_main!(async_stress_benches);