use criterion::{criterion_group, criterion_main, Criterion};
use mpc_node::protocol::message::{MessageChannel, Message, GeneratingMessage};
use mpc_node::protocol::contract::primitives::{Participants, ParticipantInfo};
use mpc_node::config::Config;
use mpc_node::config::{LocalConfig, NetworkConfig, OverrideConfig};
use mpc_node::rpc::ContractStateWatcher;
use mpc_node::node_client::{NodeClient, Options as NodeClientOptions};
use mpc_node::util::NearPublicKeyExt;
use cait_sith::protocol::Participant;
use mpc_keys::hpke;
use mpc_keys::hpke::Ciphered;
use tokio::sync::watch;
use axum::{routing::post, Router, Extension};
use axum_extra::extract::WithRejection;
use mpc_node::web::cbor::Cbor;
use mpc_node::web::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

static MSG_COUNTER: AtomicUsize = AtomicUsize::new(0);

async fn msg_handler(
    Extension(msg_channel): Extension<MessageChannel>,
    WithRejection(Cbor(encrypted), _): WithRejection<Cbor<Vec<Ciphered>>, Error>,
) {
    println!("msg_handler: received batch of size {}", encrypted.len());
    for encrypted in encrypted.into_iter() {
        let msg_channel = msg_channel.clone();
        tokio::spawn(async move {
            msg_channel.send_inbox(encrypted).await;
        });
    }
}

struct NodeFixture {
    channel: MessageChannel,
    port: u16,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

async fn start_node(
    index: u32,
    peer_index: u32,
    peer_port: u16,
    listener: tokio::net::TcpListener,
    use_quic: bool,
    cipher_sk: hpke::SecretKey,
    cipher_pk: hpke::PublicKey,
    peer_cipher_pk: hpke::PublicKey,
) -> NodeFixture {
    let sign_sk = near_crypto::SecretKey::from_seed(
        near_crypto::KeyType::ED25519,
        &format!("sign-encrypt{}", index),
    );
    let sign_pk = sign_sk.public_key();

    let peer_sign_sk = near_crypto::SecretKey::from_seed(
        near_crypto::KeyType::ED25519,
        &format!("sign-encrypt{}", peer_index),
    );
    
    let config = Config::new(LocalConfig {
        over: OverrideConfig::new(serde_json::json!({
            "message_timeout": 600000
        })),
        network: NetworkConfig {
            sign_sk: sign_sk.clone(),
            cipher_sk,
        },
    });
    let (_config_tx, config_rx) = watch::channel(config);

    let root_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::SECP256K1, "root");
    let mut participants = Participants::default();
    
    participants.insert(
        &Participant::from(index),
        ParticipantInfo {
            sign_pk: sign_pk.clone(),
            cipher_pk,
            id: Participant::from(index).into(),
            url: format!("http://127.0.0.1:8888"),
            account_id: format!("node{}.near", index).parse().unwrap(),
        },
    );
    
    participants.insert(
        &Participant::from(peer_index),
        ParticipantInfo {
            sign_pk: peer_sign_sk.public_key(),
            cipher_pk: peer_cipher_pk,
            id: Participant::from(peer_index).into(),
            url: format!("http://127.0.0.1:{}", peer_port),
            account_id: format!("node{}.near", peer_index).parse().unwrap(),
        },
    );

    let (contract_watcher, _contract_tx) = ContractStateWatcher::with_running(
        &format!("node{}.near", index).parse().unwrap(),
        root_sk.public_key().into_affine_point(),
        2,
        participants,
    );

    let (inbox, outbox, channel) = MessageChannel::new();
    let port = listener.local_addr().unwrap().port();

    let inbox_handle = tokio::spawn(inbox.run(config_rx.clone(), contract_watcher.clone()));
    
    let mut quic_server_handle = None;
    let sender = if use_quic {
        let quic_client = std::sync::Arc::new(
            mpc_node::protocol::message::quic::QuicConnectionPool::new().unwrap()
        );
        let inbox_tx = channel.inbox.clone();
        quic_server_handle = Some(mpc_node::protocol::message::quic::start_quic_server(port, inbox_tx).unwrap());
        mpc_node::protocol::message::MessageSender::Quic(quic_client)
    } else {
        let client = NodeClient::new(&NodeClientOptions::default());
        mpc_node::protocol::message::MessageSender::Http(client)
    };

    let outbox_handle = tokio::spawn(outbox.run(sender, config_rx, contract_watcher));

    let app = Router::new()
        .route("/msg", post(msg_handler))
        .layer(Extension(channel.clone()));

    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mut tasks = vec![inbox_handle, outbox_handle, server_handle];
    if let Some(h) = quic_server_handle {
        tasks.push(h);
    }

    NodeFixture {
        channel,
        port,
        tasks,
    }
}

fn bench_messaging(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let num_messages = 500;

    // 1. TCP/HTTP Benchmark
    c.bench_function(&format!("messaging send {} messages (tcp)", num_messages), |b| {
        let (node0, node1, mut rx1) = rt.block_on(async {
            let listener0 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port0 = listener0.local_addr().unwrap().port();

            let listener1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port1 = listener1.local_addr().unwrap().port();

            let (cipher_sk0, cipher_pk0) = hpke::generate();
            let (cipher_sk1, cipher_pk1) = hpke::generate();

            let node0 = start_node(0, 1, port1, listener0, false, cipher_sk0, cipher_pk0.clone(), cipher_pk1.clone()).await;
            let node1 = start_node(1, 0, port0, listener1, false, cipher_sk1, cipher_pk1, cipher_pk0).await;

            let rx1 = node1.channel.subscribe_generation().await;

            (node0, node1, rx1)
        });

        b.iter(|| {
            rt.block_on(async {
                let from = Participant::from(0);
                let to = Participant::from(1);

                println!("TCP b.iter: sending {} messages...", num_messages);
                // Send N messages
                for _ in 0..num_messages {
                    let counter = MSG_COUNTER.fetch_add(1, Ordering::SeqCst);
                    let mut data = vec![0u8; 256];
                    data[0..8].copy_from_slice(&counter.to_be_bytes());
                    let msg = Message::Generating(GeneratingMessage {
                        from,
                        data,
                    });
                    node0.channel.send(from, to, msg).await;
                }
                println!("TCP b.iter: sent all, waiting to receive...");

                // Receive N messages
                for i in 0..num_messages {
                    let _ = rx1.recv().await.unwrap();
                    if (i + 1) % 50 == 0 {
                        println!("TCP b.iter: received {} messages", i + 1);
                    }
                }
                println!("TCP b.iter: finished iteration");
            });
        });

        // Shutdown tasks for this bench run
        rt.block_on(async {
            for task in node0.tasks {
                task.abort();
                let _ = task.await;
            }
            for task in node1.tasks {
                task.abort();
                let _ = task.await;
            }
        });
    });

    // 2. QUIC Benchmark
    c.bench_function(&format!("messaging send {} messages (quic)", num_messages), |b| {
        let (node0, node1, mut rx1) = rt.block_on(async {
            let listener0 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port0 = listener0.local_addr().unwrap().port();

            let listener1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port1 = listener1.local_addr().unwrap().port();

            let (cipher_sk0, cipher_pk0) = hpke::generate();
            let (cipher_sk1, cipher_pk1) = hpke::generate();

            let node0 = start_node(0, 1, port1, listener0, true, cipher_sk0, cipher_pk0.clone(), cipher_pk1.clone()).await;
            let node1 = start_node(1, 0, port0, listener1, true, cipher_sk1, cipher_pk1, cipher_pk0).await;

            let rx1 = node1.channel.subscribe_generation().await;

            (node0, node1, rx1)
        });

        b.iter(|| {
            rt.block_on(async {
                let from = Participant::from(0);
                let to = Participant::from(1);

                println!("QUIC b.iter: sending {} messages...", num_messages);
                // Send N messages
                for _ in 0..num_messages {
                    let counter = MSG_COUNTER.fetch_add(1, Ordering::SeqCst);
                    let mut data = vec![0u8; 256];
                    data[0..8].copy_from_slice(&counter.to_be_bytes());
                    let msg = Message::Generating(GeneratingMessage {
                        from,
                        data,
                    });
                    node0.channel.send(from, to, msg).await;
                }
                println!("QUIC b.iter: sent all, waiting to receive...");

                // Receive N messages
                for i in 0..num_messages {
                    let _ = rx1.recv().await.unwrap();
                    if (i + 1) % 50 == 0 {
                        println!("QUIC b.iter: received {} messages", i + 1);
                    }
                }
                println!("QUIC b.iter: finished iteration");
            });
        });

        // Shutdown tasks for this bench run
        rt.block_on(async {
            for task in node0.tasks {
                task.abort();
                let _ = task.await;
            }
            for task in node1.tasks {
                task.abort();
                let _ = task.await;
            }
        });
    });
}

criterion_group!(benches, bench_messaging);
criterion_main!(benches);
