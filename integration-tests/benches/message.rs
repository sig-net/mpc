use std::time::Duration;

use cait_sith::protocol::Participant;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use mpc_keys::hpke;
use mpc_node::protocol::{
    contract::primitives::{ParticipantMap, Participants},
    message::{Message, MessageChannel, MessageOutbox, SignedMessage, TripleMessage},
    ParticipantInfo,
};
use tokio::sync::mpsc;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn participants(len: usize) -> Participants {
    let (_cipher_sk, cipher_pk) = mpc_keys::hpke::generate();
    let sign_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
    let mut participants = Participants::default();
    for i in 0..len {
        let id = Participant::from(i as u32);
        participants.insert(
            &id,
            ParticipantInfo {
                sign_pk: sign_sk.public_key(),
                cipher_pk: cipher_pk.clone(),
                id: id.into(),
                url: format!("http://localhost:{}", 3030 + i),
                account_id: format!("test{i}.near").parse().unwrap(),
            },
        );
    }
    participants
}

/// Create a batch of TripleMessages for benchmarking
fn create_message_batch(count: usize, data_size: usize) -> Vec<Message> {
    let from = Participant::from(0);
    (0..count)
        .map(|i| {
            Message::Triple(TripleMessage {
                id: i as u64,
                epoch: 1,
                from,
                data: vec![128u8; data_size],
                timestamp: 1234567,
            })
        })
        .collect()
}

/// Benchmark raw message encryption
fn bench_message_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_encrypt");
    let from = Participant::from(0);
    let sign_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
    let (_cipher_sk, cipher_pk) = hpke::generate();

    // Benchmark different message counts
    for count in [1, 10, 50, 100] {
        // Benchmark different data sizes
        for data_size in [256, 1024, 4096] {
            let batch = create_message_batch(count, data_size);
            let total_size: usize = batch.iter().map(|m| m.size()).sum();

            group.throughput(Throughput::Bytes(total_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("count_{count}"), format!("data_{data_size}")),
                &batch,
                |b, batch| {
                    b.iter(|| {
                        let encrypted =
                            SignedMessage::encrypt(batch, from, &sign_sk, &cipher_pk).unwrap();
                        black_box(encrypted)
                    })
                },
            );
        }
    }
    group.finish();
}

/// Benchmark raw message decryption
fn bench_message_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_decrypt");
    let from = Participant::from(0);
    let sign_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
    let (cipher_sk, cipher_pk) = hpke::generate();
    let participants = participants(1);
    let participant_map = ParticipantMap::One(participants);

    for count in [1, 10, 50, 100] {
        for data_size in [256, 1024, 4096] {
            let batch = create_message_batch(count, data_size);
            let total_size: usize = batch.iter().map(|m| m.size()).sum();
            let encrypted = SignedMessage::encrypt(&batch, from, &sign_sk, &cipher_pk).unwrap();

            group.throughput(Throughput::Bytes(total_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("count_{count}"), format!("data_{data_size}")),
                &encrypted,
                |b, encrypted| {
                    b.iter(|| {
                        let decrypted: Vec<Message> =
                            SignedMessage::decrypt(encrypted, &cipher_sk, &participant_map)
                                .unwrap();
                        black_box(decrypted)
                    })
                },
            );
        }
    }
    group.finish();
}

/// Benchmark MessageChannel send (outbox queue ingress)
fn bench_message_channel_send(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_channel_send");
    let rt = runtime();

    let from = Participant::from(0);
    let to = Participant::from(1);

    for data_size in [256, 1024, 4096] {
        // Create a fresh channel for each benchmark to avoid channel saturation
        let (_inbox, _outbox, channel) = MessageChannel::new();

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("single_message", format!("data_{data_size}")),
            &data_size,
            |b, &data_size| {
                b.iter(|| {
                    let msg = Message::Triple(TripleMessage {
                        id: 1,
                        epoch: 1,
                        from,
                        data: vec![128u8; data_size],
                        timestamp: 1234567,
                    });
                    rt.block_on(async {
                        channel.send(from, to, msg).await;
                    })
                })
            },
        );
    }

    // Benchmark burst sends (multiple messages in quick succession)
    for count in [10, 100, 1000] {
        // Create a fresh channel for each benchmark
        let (_inbox, _outbox, channel) = MessageChannel::new();

        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::new("burst", format!("count_{count}")),
            &count,
            |b, &count| {
                b.iter(|| {
                    rt.block_on(async {
                        for i in 0..count {
                            let msg = Message::Triple(TripleMessage {
                                id: i as u64,
                                epoch: 1,
                                from,
                                data: vec![128u8; 256],
                                timestamp: 1234567,
                            });
                            channel.send(from, to, msg).await;
                        }
                    })
                })
            },
        );
    }

    group.finish();
}

/// Benchmark MessageInbox ingress (encrypted messages coming in)
fn bench_inbox_ingress(c: &mut Criterion) {
    let mut group = c.benchmark_group("inbox_ingress");
    let rt = runtime();

    let from = Participant::from(0);
    let sign_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
    let (_cipher_sk, cipher_pk) = hpke::generate();

    for count in [1, 10, 50, 100] {
        for data_size in [256, 1024, 4096] {
            let batch = create_message_batch(count, data_size);
            let total_size: usize = batch.iter().map(|m| m.size()).sum();

            group.throughput(Throughput::Bytes(total_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("count_{count}"), format!("data_{data_size}")),
                &(count, data_size),
                |b, &(count, data_size)| {
                    // Create a fresh channel for each benchmark
                    let (_inbox, _outbox, channel) = MessageChannel::new();
                    let batch = create_message_batch(count, data_size);

                    b.iter(|| {
                        rt.block_on(async {
                            // Encrypt and send a fresh message each time
                            let encrypted =
                                SignedMessage::encrypt(&batch, from, &sign_sk, &cipher_pk).unwrap();
                            channel.inbox.send(encrypted).await.unwrap();
                        })
                    })
                },
            );
        }
    }

    group.finish();
}

/// Benchmark end-to-end throughput: measure how many messages can be encrypted per second
fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.measurement_time(Duration::from_secs(10));

    let from = Participant::from(0);
    let sign_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
    let (cipher_sk, cipher_pk) = hpke::generate();
    let participants = participants(1);
    let participant_map = ParticipantMap::One(participants);

    // Measure messages per second for typical workload
    let data_size = 1024; // Typical message size
    let batch_size = 50; // Typical batch size

    let batch = create_message_batch(batch_size, data_size);

    group.throughput(Throughput::Elements(batch_size as u64));
    group.bench_function("encrypt_decrypt_cycle", |b| {
        b.iter(|| {
            let encrypted = SignedMessage::encrypt(&batch, from, &sign_sk, &cipher_pk).unwrap();
            let decrypted: Vec<Message> =
                SignedMessage::decrypt(&encrypted, &cipher_sk, &participant_map).unwrap();
            black_box(decrypted)
        })
    });

    group.finish();
}

/// Benchmark message serialization (CBOR encoding)
fn bench_message_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_serialization");

    for count in [1, 10, 50, 100] {
        for data_size in [256, 1024, 4096] {
            let batch = create_message_batch(count, data_size);
            let total_size: usize = batch.iter().map(|m| m.size()).sum();

            group.throughput(Throughput::Bytes(total_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("count_{count}"), format!("data_{data_size}")),
                &batch,
                |b, batch| {
                    b.iter(|| {
                        let mut buf = Vec::new();
                        ciborium::into_writer(batch, &mut buf).unwrap();
                        black_box(buf)
                    })
                },
            );
        }
    }

    group.finish();
}

/// Benchmark message deserialization (CBOR decoding)
fn bench_message_deserialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_deserialization");

    for count in [1, 10, 50, 100] {
        for data_size in [256, 1024, 4096] {
            let batch = create_message_batch(count, data_size);
            let total_size: usize = batch.iter().map(|m| m.size()).sum();

            let mut buf = Vec::new();
            ciborium::into_writer(&batch, &mut buf).unwrap();

            group.throughput(Throughput::Bytes(total_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("count_{count}"), format!("data_{data_size}")),
                &buf,
                |b, buf| {
                    b.iter(|| {
                        let decoded: Vec<Message> = ciborium::from_reader(&buf[..]).unwrap();
                        black_box(decoded)
                    })
                },
            );
        }
    }

    group.finish();
}

/// Benchmark high-throughput message channel stress test
fn bench_channel_stress(c: &mut Criterion) {
    let mut group = c.benchmark_group("channel_stress");
    group.measurement_time(Duration::from_secs(10));

    let rt = runtime();
    let from = Participant::from(0);
    let to = Participant::from(1);

    // Test maximum sustainable throughput
    for message_count in [1000, 5000, 10000] {
        let (_inbox, _outbox, channel) = MessageChannel::new();

        group.throughput(Throughput::Elements(message_count as u64));
        group.bench_with_input(
            BenchmarkId::new("sustained_send", message_count.to_string()),
            &message_count,
            |b, &message_count| {
                b.iter(|| {
                    rt.block_on(async {
                        for i in 0..message_count {
                            let msg = Message::Triple(TripleMessage {
                                id: i as u64,
                                epoch: 1,
                                from,
                                data: vec![128u8; 256],
                                timestamp: 1234567,
                            });
                            channel.send(from, to, msg).await;
                        }
                    })
                })
            },
        );
    }

    group.finish();
}

/// Benchmark MessageOutbox full processing pipeline: queue → compact → encrypt
fn bench_outbox_process(c: &mut Criterion) {
    let mut group = c.benchmark_group("outbox_process");

    let from = Participant::from(0);
    let to = Participant::from(1);
    let sign_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
    let participants = participants(2);

    for count in [10, 50, 100, 500] {
        for data_size in [256, 1024, 4096] {
            let total_size = count * (std::mem::size_of::<TripleMessage>() + data_size);

            group.throughput(Throughput::Bytes(total_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("count_{count}"), format!("data_{data_size}")),
                &(count, data_size),
                |b, &(count, data_size)| {
                    b.iter(|| {
                        // Create a fresh outbox for each iteration
                        let (_tx, rx) = mpsc::channel(1024 * 1024);
                        let mut outbox = MessageOutbox::new(rx);

                        // Queue messages
                        for i in 0..count {
                            let msg = Message::Triple(TripleMessage {
                                id: i as u64,
                                epoch: 1,
                                from,
                                data: vec![128u8; data_size],
                                timestamp: 1234567,
                            });
                            outbox.queue_message(from, to, msg);
                        }

                        // Process: compact + encrypt
                        let encrypted = outbox.process_outgoing(&sign_sk, &participants);
                        black_box(encrypted)
                    })
                },
            );
        }
    }

    group.finish();
}

/// Benchmark MessageOutbox with multiple destination participants
fn bench_outbox_multi_participant(c: &mut Criterion) {
    let mut group = c.benchmark_group("outbox_multi_participant");

    let from = Participant::from(0);
    let sign_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");

    // Test with different numbers of destination participants
    for num_participants in [2, 4, 8, 12] {
        let participants = participants(num_participants);
        let messages_per_participant = 50;
        let data_size = 1024;
        let total_messages = (num_participants - 1) * messages_per_participant; // exclude self
        let total_size = total_messages * (std::mem::size_of::<TripleMessage>() + data_size);

        group.throughput(Throughput::Bytes(total_size as u64));
        group.bench_with_input(
            BenchmarkId::new("participants", num_participants.to_string()),
            &num_participants,
            |b, &num_participants| {
                b.iter(|| {
                    let (_tx, rx) = mpsc::channel(1024 * 1024);
                    let mut outbox = MessageOutbox::new(rx);

                    // Queue messages to each participant
                    for to_id in 1..num_participants {
                        let to = Participant::from(to_id as u32);
                        for i in 0..messages_per_participant {
                            let msg = Message::Triple(TripleMessage {
                                id: i as u64,
                                epoch: 1,
                                from,
                                data: vec![128u8; data_size],
                                timestamp: 1234567,
                            });
                            outbox.queue_message(from, to, msg);
                        }
                    }

                    let encrypted = outbox.process_outgoing(&sign_sk, &participants);
                    black_box(encrypted)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark MessageInbox full processing pipeline: decrypt → filter → (ready to publish)
fn bench_inbox_process(c: &mut Criterion) {
    let mut group = c.benchmark_group("inbox_process");

    let from = Participant::from(0);
    let sign_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "sign-encrypt0");
    let (cipher_sk, cipher_pk) = hpke::generate();
    let participants = participants(1);
    let participant_map = ParticipantMap::One(participants);
    let message_timeout = Duration::from_secs(60);

    for count in [1, 10, 50, 100] {
        for data_size in [256, 1024, 4096] {
            let batch = create_message_batch(count, data_size);
            let total_size: usize = batch.iter().map(|m| m.size()).sum();

            group.throughput(Throughput::Bytes(total_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("count_{count}"), format!("data_{data_size}")),
                &(count, data_size),
                |b, &(count, data_size)| {
                    b.iter(|| {
                        // Create a fresh inbox for each iteration
                        let (_inbox, _outbox, _channel) = MessageChannel::new();
                        let (_inbox_tx, inbox_rx) = mpsc::channel(1024);
                        let (_filter_tx, filter_rx) = mpsc::channel(1024);
                        let (_subscribe_tx, subscribe_rx) = mpsc::channel(1024);
                        let mut inbox = mpc_node::protocol::message::MessageInbox::new(
                            inbox_rx,
                            filter_rx,
                            subscribe_rx,
                        );

                        // Encrypt the batch
                        let batch = create_message_batch(count, data_size);
                        let encrypted =
                            SignedMessage::encrypt(&batch, from, &sign_sk, &cipher_pk).unwrap();

                        // Process: decrypt + filter (sync version, no publish)
                        let messages = inbox.process_incoming_sync(
                            encrypted,
                            message_timeout,
                            &cipher_sk,
                            &participant_map,
                        );
                        black_box(messages)
                    })
                },
            );
        }
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_message_encrypt,
    bench_message_decrypt,
    bench_message_channel_send,
    bench_inbox_ingress,
    bench_message_serialization,
    bench_message_deserialization,
    bench_throughput,
    bench_channel_stress,
    bench_outbox_process,
    bench_outbox_multi_participant,
    bench_inbox_process,
);
criterion_main!(benches);
