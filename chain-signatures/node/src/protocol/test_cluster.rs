use std::collections::HashMap;
use std::time::Duration;

use cait_sith::protocol::{Action, Participant, Protocol};
use cait_sith::{KeygenOutput, PresignArguments, PresignOutput};
use chrono::Utc;
use k256::Secp256k1;
use tokio::task::JoinHandle;

use crate::config::{Config, LocalConfig, NetworkConfig, OverrideConfig};
use crate::protocol::contract::primitives::Participants;
use crate::protocol::message::{
    ArtifactMessage, GeneratingMessage, MessageChannel, PresignatureMessage, SendMessage,
    SignedMessage, TripleMessage,
};
use crate::protocol::presignature::FullPresignatureId;
use crate::protocol::ParticipantInfo;
use crate::rpc::ContractStateWatcher;
use crate::util::NearPublicKeyExt;
use mpc_keys::hpke;

pub struct TestNode {
    pub participant: Participant,
    pub account_id: near_account_id::AccountId,
    pub channel: MessageChannel,
    pub keygen_out: KeygenOutput<Secp256k1>,
    pub sign_sk: near_crypto::SecretKey,
    pub cipher_sk: hpke::SecretKey,
    pub cipher_pk: hpke::PublicKey,
    _inbox_handle: JoinHandle<()>,
}

pub struct TestCluster {
    pub threshold: usize,
    pub participants: Vec<Participant>,
    pub nodes: HashMap<Participant, TestNode>,
    _router_handles: Vec<JoinHandle<()>>,
}

impl TestCluster {
    pub async fn new(threshold: usize, total: usize) -> anyhow::Result<Self> {
        let participants: Vec<Participant> = (0..total).map(|i| Participant::from(i as u32)).collect();
        let mut sign_sks = HashMap::new();
        let mut cipher_sks = HashMap::new();
        let mut cipher_pks = HashMap::new();
        let mut account_ids = HashMap::new();
        let mut participant_map = Participants::default();

        for (i, &p) in participants.iter().enumerate() {
            let sign_sk = near_crypto::SecretKey::from_seed(
                near_crypto::KeyType::ED25519,
                &format!("test_cluster_sign_{i}"),
            );
            let (cipher_sk, cipher_pk) = hpke::generate();
            let account_id: near_account_id::AccountId = format!("node_{i}.near").parse().unwrap();

            participant_map.insert(
                &p,
                ParticipantInfo {
                    sign_pk: sign_sk.public_key(),
                    cipher_pk: cipher_pk.clone(),
                    id: p.into(),
                    url: format!("http://localhost:{}", 3000 + i),
                    account_id: account_id.clone(),
                },
            );

            sign_sks.insert(p, sign_sk);
            cipher_sks.insert(p, cipher_sk);
            cipher_pks.insert(p, cipher_pk);
            account_ids.insert(p, account_id);
        }

        let root_sk = near_crypto::SecretKey::from_seed(near_crypto::KeyType::SECP256K1, "root");
        let mut channels = HashMap::new();
        let mut outbox_rxs = Vec::new();
        let mut inbox_handles = HashMap::new();

        for &p in &participants {
            let (cipher_sk, _) = (cipher_sks[&p].clone(), cipher_pks[&p].clone());
            let sign_sk = sign_sks[&p].clone();
            let (_config_tx, config_rx) = Config::channel(LocalConfig {
                over: OverrideConfig::default(),
                network: NetworkConfig {
                    sign_sk,
                    cipher_sk,
                },
            });
            let (contract_watcher, _contract_tx) = ContractStateWatcher::with_running(
                &account_ids[&p],
                root_sk.public_key().into_affine_point(),
                threshold,
                participant_map.clone(),
            );

            let (inbox, mut outbox, channel) = MessageChannel::new();
            let inbox_handle = tokio::spawn(inbox.run(config_rx, contract_watcher));
            let outbox_rx = outbox.take_outgoing_receiver();

            channels.insert(p, channel);
            outbox_rxs.push((p, outbox_rx));
            inbox_handles.insert(p, inbox_handle);
        }

        // Spawn mock in-memory network router
        let mut router_handles = Vec::new();
        for (from, mut rx) in outbox_rxs {
            let sign_sk = sign_sks[&from].clone();
            let peer_cipher_pks = cipher_pks.clone();
            let peer_channels = channels.clone();

            let handle = tokio::spawn(async move {
                while let Some(SendMessage {
                    message,
                    from,
                    to,
                    ..
                }) = rx.recv().await
                {
                    if let Some(to_cipher_pk) = peer_cipher_pks.get(&to) {
                        if let Ok(encrypted) =
                            SignedMessage::encrypt(&[message], from, &sign_sk, to_cipher_pk)
                        {
                            if let Some(to_channel) = peer_channels.get(&to) {
                                to_channel.send_inbox(encrypted).await;
                            }
                        }
                    }
                }
            });
            router_handles.push(handle);
        }

        // Run keygen across all nodes
        let mut keygen_tasks = Vec::new();
        for &p in &participants {
            let channel = channels[&p].clone();
            let parts = participants.clone();
            keygen_tasks.push(tokio::spawn(async move {
                drive_keygen(p, threshold, parts, channel, Duration::from_secs(10)).await
            }));
        }

        let mut keygen_outs = HashMap::new();
        for (task, &p) in keygen_tasks.into_iter().zip(participants.iter()) {
            let out = task.await??;
            keygen_outs.insert(p, out);
        }

        let mut nodes = HashMap::new();
        for &p in &participants {
            let node = TestNode {
                participant: p,
                account_id: account_ids.remove(&p).unwrap(),
                channel: channels.remove(&p).unwrap(),
                keygen_out: keygen_outs.remove(&p).unwrap(),
                sign_sk: sign_sks.remove(&p).unwrap(),
                cipher_sk: cipher_sks.remove(&p).unwrap(),
                cipher_pk: cipher_pks.remove(&p).unwrap(),
                _inbox_handle: inbox_handles.remove(&p).unwrap(),
            };
            nodes.insert(p, node);
        }

        Ok(Self {
            threshold,
            participants,
            nodes,
            _router_handles: router_handles,
        })
    }
}

async fn drive_keygen(
    me: Participant,
    threshold: usize,
    participants: Vec<Participant>,
    channel: MessageChannel,
    timeout: Duration,
) -> anyhow::Result<KeygenOutput<Secp256k1>> {
    let mut protocol = cait_sith::keygen::<Secp256k1>(&participants, me, threshold)?;
    let mut rx = channel.subscribe_generation().await;
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let action = protocol.poke()?;
        match action {
            Action::Wait => {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                let msg = tokio::time::timeout(remaining, rx.recv())
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("keygen channel closed"))?;
                protocol.message(msg.from, msg.data);
            }
            Action::SendMany(data) => {
                for to in &participants {
                    if *to == me {
                        continue;
                    }
                    channel
                        .send(
                            me,
                            *to,
                            GeneratingMessage {
                                from: me,
                                data: data.clone(),
                            },
                        )
                        .await;
                }
            }
            Action::SendPrivate(to, data) => {
                channel
                    .send(
                        me,
                        to,
                        GeneratingMessage {
                            from: me,
                            data,
                        },
                    )
                    .await;
            }
            Action::Return(out) => return Ok(out),
        }
    }
}

pub async fn drive_stacked_presignature(
    me: Participant,
    threshold: usize,
    participants: Vec<Participant>,
    id: FullPresignatureId,
    keygen_out: KeygenOutput<Secp256k1>,
    channel: MessageChannel,
    timeout: Duration,
) -> anyhow::Result<PresignOutput<Secp256k1>> {
    let mut triple_protocol =
        cait_sith::triples::generate_triple_many::<Secp256k1, 2>(&participants, me, threshold)?;
    let mut rx = channel.subscribe_artifact(id.id).await;
    let deadline = tokio::time::Instant::now() + timeout;

    let mut early_presign_messages: Vec<PresignatureMessage> = Vec::new();

    // Stage 1: Triples in RAM
    let triple_pair = loop {
        let action = triple_protocol.poke()?;
        match action {
            Action::Wait => {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                let msg = tokio::time::timeout(remaining, rx.recv())
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("artifact channel closed in stage 1"))?;
                match msg {
                    ArtifactMessage::Triple(msg) => {
                        triple_protocol.message(msg.from, msg.data);
                    }
                    ArtifactMessage::Presignature(msg) => {
                        early_presign_messages.push(msg);
                    }
                }
            }
            Action::SendMany(data) => {
                for to in &participants {
                    if *to == me {
                        continue;
                    }
                    channel
                        .send(
                            me,
                            *to,
                            TripleMessage {
                                id: id.id,
                                epoch: 0,
                                from: me,
                                data: data.clone(),
                                timestamp: Utc::now().timestamp() as u64,
                            },
                        )
                        .await;
                }
            }
            Action::SendPrivate(to, data) => {
                channel
                    .send(
                        me,
                        to,
                        TripleMessage {
                            id: id.id,
                            epoch: 0,
                            from: me,
                            data,
                            timestamp: Utc::now().timestamp() as u64,
                        },
                    )
                    .await;
            }
            Action::Return(outputs) => {
                let [first, second, ..] = &outputs[..] else {
                    anyhow::bail!("not enough triples in output");
                };
                break (first.clone(), second.clone());
            }
        }
    };

    // Stage 2: Cait-Sith Presignature directly consuming RAM triples
    let mut presign_protocol = cait_sith::presign(
        &participants,
        me,
        &participants,
        me,
        PresignArguments {
            triple0: (triple_pair.0 .0, triple_pair.0 .1),
            triple1: (triple_pair.1 .0, triple_pair.1 .1),
            keygen_out,
            threshold,
        },
    )?;

    for msg in early_presign_messages {
        presign_protocol.message(msg.from, msg.data);
    }

    loop {
        let action = presign_protocol.poke()?;
        match action {
            Action::Wait => {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                let msg = tokio::time::timeout(remaining, rx.recv())
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("artifact channel closed in stage 2"))?;
                match msg {
                    ArtifactMessage::Presignature(msg) => {
                        presign_protocol.message(msg.from, msg.data);
                    }
                    ArtifactMessage::Triple(_) => {}
                }
            }
            Action::SendMany(data) => {
                for to in &participants {
                    if *to == me {
                        continue;
                    }
                    channel
                        .send(
                            me,
                            *to,
                            PresignatureMessage {
                                id: id.id,
                                pair_id: id.id,
                                epoch: 0,
                                from: me,
                                data: data.clone(),
                                timestamp: Utc::now().timestamp() as u64,
                            },
                        )
                        .await;
                }
            }
            Action::SendPrivate(to, data) => {
                channel
                    .send(
                        me,
                        to,
                        PresignatureMessage {
                            id: id.id,
                            pair_id: id.id,
                            epoch: 0,
                            from: me,
                            data,
                            timestamp: Utc::now().timestamp() as u64,
                        },
                    )
                    .await;
            }
            Action::Return(out) => return Ok(out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cluster_initialization_and_keygen() {
        let cluster = TestCluster::new(2, 3)
            .await
            .expect("cluster creation failed");

        assert_eq!(cluster.nodes.len(), 3);
        let first_pk = cluster.nodes[&Participant::from(0)].keygen_out.public_key;
        for p in &cluster.participants {
            assert_eq!(cluster.nodes[p].keygen_out.public_key, first_pk);
        }
    }

    #[tokio::test]
    async fn test_stacked_presignature_generation() {
        let cluster = TestCluster::new(2, 3)
            .await
            .expect("cluster creation failed");

        let id = FullPresignatureId::new(rand::random());
        let participants = cluster.participants.clone();

        let mut tasks = Vec::new();
        for &p in &participants {
            let channel = cluster.nodes[&p].channel.clone();
            let keygen_out = cluster.nodes[&p].keygen_out.clone();
            let parts = participants.clone();
            tasks.push(tokio::spawn(async move {
                drive_stacked_presignature(
                    p,
                    2,
                    parts,
                    id,
                    keygen_out,
                    channel,
                    Duration::from_secs(15),
                )
                .await
            }));
        }

        let mut presign_outs = Vec::new();
        for task in tasks {
            let out = task.await.unwrap().expect("presignature generation failed");
            presign_outs.push(out);
        }

        assert_eq!(presign_outs.len(), 3);
        let first_r = presign_outs[0].big_r;
        for out in &presign_outs {
            assert_eq!(out.big_r, first_r);
        }
    }
}
